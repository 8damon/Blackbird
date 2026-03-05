using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;

namespace SleepwalkerInterface
{
    public partial class DirectSyscallSuspectWindow : Window
    {
        private readonly ObservableCollection<DirectSyscallEntry> _entries = new();
        private readonly ObservableCollection<KeyValueRow> _argumentRows = new();
        private readonly ObservableCollection<KeyValueRow> _contextRows = new();
        private DirectSyscallEntry? _selectedEntry;

        private DirectSyscallSuspectWindow(string detection, IEnumerable<GroupedEventDetailRow> rows)
        {
            InitializeComponent();
            WindowThemeHelper.ApplyDarkTitleBar(this);

            HeaderBlock.Text = $"Direct Syscall Suspects: {detection}";
            ICollectionView entriesView = CollectionViewSource.GetDefaultView(_entries);
            entriesView.GroupDescriptions.Add(new PropertyGroupDescription(nameof(DirectSyscallEntry.SyscallName)));
            SuspectsGrid.ItemsSource = entriesView;
            ArgumentsGrid.ItemsSource = _argumentRows;
            ContextGrid.ItemsSource = _contextRows;

            foreach (GroupedEventDetailRow row in rows.OrderByDescending(x => x.TimestampUtc))
            {
                _entries.Add(ParseEntry(row));
            }

            SummaryBlock.Text = _entries.Count == 0
                ? "No suspect entries"
                : $"{_entries.Count} suspect entr{(_entries.Count == 1 ? "y" : "ies")} across {_entries.Select(x => x.SyscallName).Distinct(StringComparer.OrdinalIgnoreCase).Count()} syscall groups";

            if (_entries.Count > 0)
            {
                SuspectsGrid.SelectedIndex = 0;
                UpdateDetails(_entries[0]);
            }
            else
            {
                UpdateDetails(null);
            }
        }

        internal static bool IsDirectSyscallDetection(string detection)
        {
            if (string.IsNullOrWhiteSpace(detection))
            {
                return false;
            }

            return detection.Contains("DIRECT_SYSCALL", StringComparison.OrdinalIgnoreCase) ||
                   detection.Contains("DIRECT-SYSCALL", StringComparison.OrdinalIgnoreCase) ||
                   detection.Contains("SUSPECT_HANDLE_OPERATION", StringComparison.OrdinalIgnoreCase) ||
                   detection.Contains("ANOMALY_ON_HANDLE_OP", StringComparison.OrdinalIgnoreCase);
        }

        internal static void ShowForGroup(
            Window? owner,
            string detection,
            IEnumerable<GroupedEventDetailRow> rows)
        {
            var window = new DirectSyscallSuspectWindow(detection, rows);
            if (owner != null && !ReferenceEquals(owner, window))
            {
                window.Owner = owner;
            }

            window.Show();
            window.Activate();
        }

        private static DirectSyscallEntry ParseEntry(GroupedEventDetailRow row)
        {
            string raw = row.Details ?? string.Empty;
            string evidence = SliceBetween(raw, "evidence=", " hits=");
            if (string.IsNullOrWhiteSpace(evidence))
            {
                evidence = raw;
            }

            string corrAccessToken = ReadTokenValue(raw, "corrAccess=0x");
            string accessToken = ReadTokenValue(evidence, "access=0x");
            string accessHex = string.IsNullOrWhiteSpace(accessToken) ? corrAccessToken : accessToken;
            uint access = TryParseHexU32(accessHex);

            string originAddress = ReadTokenValue(evidence, "origin=");
            string originProtect = ReadTokenValue(evidence, "protect=0x");
            string moduleName = ReadTokenValue(evidence, "module=");
            string pageBase = ReadTokenValue(evidence, "pageBase=");
            string allocationBaseToken = ReadTokenValue(evidence, "allocationBase=");
            string regionSizeToken = ReadTokenValue(evidence, "regionSize=");
            string regionProtectToken = ReadTokenValue(evidence, "regionProtect=0x");
            string regionStateToken = ReadTokenValue(evidence, "regionState=0x");
            string regionTypeToken = ReadTokenValue(evidence, "regionType=0x");
            string path = SliceBetween(evidence, "path=", " stack0=");
            if (string.IsNullOrWhiteSpace(path))
            {
                path = row.Target;
            }

            string stack0 = ReadTokenValue(evidence, "stack0=");
            string stack1 = ReadTokenValue(evidence, "stack1=");
            string sampleHex = SliceBetween(evidence, "deepSample=", " sampleDisasmHint=");
            if (string.IsNullOrWhiteSpace(sampleHex))
            {
                sampleHex = "<none>";
            }

            byte[] sampleBytes = ParseHexBytes(sampleHex);
            ulong originAddressRaw = TryParseHexU64(originAddress);
            ulong regionBase = TryParseHexU64(allocationBaseToken);
            ulong regionSize = TryParseHexU64(regionSizeToken);
            uint regionProtect = TryParseHexU32(regionProtectToken);
            uint regionState = TryParseHexU32(regionStateToken);
            uint regionType = TryParseHexU32(regionTypeToken);
            string disasmHint = ReadRestAfter(evidence, "sampleDisasmHint=");
            string disasm = EventDetailFormatting.FormatSampleDisassembly(
                sampleBytes,
                sampleBytes.Length,
                originAddressRaw,
                path,
                regionBase,
                regionSize,
                regionProtect,
                regionState,
                regionType);
            if (sampleBytes.Length == 0)
            {
                disasm = string.IsNullOrWhiteSpace(disasmHint) ? "unavailable" : disasmHint;
            }
            else if (!string.IsNullOrWhiteSpace(disasmHint))
            {
                disasm = $"hint: {disasmHint}\n{disasm}";
            }

            (uint syscallId, bool hasId) = ExtractSyscallId(sampleBytes);
            string apiGuess = GuessSyscallApi(row.Detection, access, raw, evidence);
            string syscallLabel = hasId
                ? $"{apiGuess} (id=0x{syscallId:X})"
                : apiGuess;

            string args = $"syscall={syscallLabel}; actor={row.Actor}; target={row.Target}; desiredAccess=0x{access:X8} ({EventDetailFormatting.DescribeHandleAccess(access)})";
            string registerCapture = BuildRegisterCapture(evidence, sampleBytes, originAddress);
            string captureFlags = ReadTokenValue(evidence, "captureFlags=");
            string fullFrameCount = ReadTokenValue(evidence, "fullFrameCount=");
            string fullFrames = ReadTokenValue(evidence, "fullFrames=");
            string stackSnapshotAddress = ReadTokenValue(evidence, "stackSnapshotAddress=");
            string stackSnapshotSize = ReadTokenValue(evidence, "stackSnapshotSize=");
            string context = $"detection={row.Detection}; targetObject={path}; module={moduleName}";
            if (!string.IsNullOrWhiteSpace(registerCapture))
            {
                context = $"{context}; registers={registerCapture}";
            }
            if (!string.IsNullOrWhiteSpace(captureFlags))
            {
                context = $"{context}; captureFlags={captureFlags}";
            }
            if (!string.IsNullOrWhiteSpace(fullFrameCount))
            {
                context = $"{context}; fullFrameCount={fullFrameCount}";
            }
            if (!string.IsNullOrWhiteSpace(fullFrames))
            {
                context = $"{context}; fullFrames={fullFrames}";
            }
            if (!string.IsNullOrWhiteSpace(stackSnapshotAddress))
            {
                context = $"{context}; stackSnapshotAddress={stackSnapshotAddress}";
            }
            if (!string.IsNullOrWhiteSpace(stackSnapshotSize))
            {
                context = $"{context}; stackSnapshotSize={stackSnapshotSize}";
            }
            string addresses =
                $"origin={originAddress}; protect=0x{originProtect}; module={moduleName}; pageBase={pageBase}; allocationBase={allocationBaseToken}; regionSize={regionSizeToken}; regionProtect=0x{regionProtectToken}; regionState=0x{regionStateToken}; regionType=0x{regionTypeToken}; stack0={stack0}; stack1={stack1}; stackSnapshotAddress={stackSnapshotAddress}; stackSnapshotSize={stackSnapshotSize}; path={path}";

            return new DirectSyscallEntry
            {
                TimestampUtc = row.TimestampUtc,
                Detection = row.Detection,
                Actor = row.Actor,
                Target = row.Target,
                TargetObject = path,
                SyscallName = apiGuess,
                SyscallLabel = syscallLabel,
                Arguments = args,
                Context = context,
                Addresses = addresses,
                StubHex = sampleHex,
                Disassembly = disasm,
                Raw = raw
            };
        }

        private static string GuessSyscallApi(string detection, uint access, string raw, string evidence)
        {
            if (evidence.Contains("DUPLICATE_OPERATION", StringComparison.OrdinalIgnoreCase) ||
                raw.Contains("INTENT_DUP_HANDLE", StringComparison.OrdinalIgnoreCase))
            {
                return "NtDuplicateObject";
            }

            if ((access & 0x00000010u) != 0 || (access & 0x00000002u) != 0 ||
                (access & 0x001F03FFu) == 0x001F03FFu)
            {
                return "NtOpenThread";
            }

            if (detection.Contains("HANDLE", StringComparison.OrdinalIgnoreCase) ||
                (access & 0x001F0FFFu) == 0x001F0FFFu ||
                access != 0)
            {
                return "NtOpenProcess";
            }

            return "Direct syscall suspect";
        }

        private static (uint Id, bool HasId) ExtractSyscallId(byte[] bytes)
        {
            if (bytes.Length < 11)
            {
                return (0, false);
            }

            for (int i = 0; i <= bytes.Length - 11; i += 1)
            {
                if (bytes[i] == 0x4C &&
                    bytes[i + 1] == 0x8B &&
                    bytes[i + 2] == 0xD1 &&
                    bytes[i + 3] == 0xB8 &&
                    bytes[i + 8] == 0x0F &&
                    bytes[i + 9] == 0x05)
                {
                    uint id = (uint)(bytes[i + 4] |
                                     (bytes[i + 5] << 8) |
                                     (bytes[i + 6] << 16) |
                                     (bytes[i + 7] << 24));
                    return (id, true);
                }
            }

            return (0, false);
        }

        private static string BuildRegisterCapture(string evidence, byte[] bytes, string originAddress)
        {
            var parts = new List<string>();
            string[] keys =
            {
                "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10",
                "r11", "r12", "r13", "r14", "r15", "rip", "eflags", "dr0", "dr1", "dr2", "dr3", "dr6", "dr7"
            };
            foreach (string key in keys)
            {
                string value = ReadTokenValue(evidence, key + "=");
                if (!string.IsNullOrWhiteSpace(value) && !IsZeroHexValue(value))
                {
                    parts.Add($"{key.ToUpperInvariant()}={value}");
                }
            }

            (uint syscallId, bool hasId) = ExtractSyscallId(bytes);
            if (hasId)
            {
                parts.Add($"EAX=0x{syscallId:X}");
                parts.Add("R10=RCX");
            }

            if (!string.IsNullOrWhiteSpace(originAddress))
            {
                parts.Add($"RIP={originAddress}");
            }

            return parts.Count == 0 ? string.Empty : string.Join(", ", parts);
        }

        private static bool IsZeroHexValue(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return true;
            }

            string trimmed = value.Trim();
            if (trimmed.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            {
                trimmed = trimmed[2..];
            }

            return ulong.TryParse(trimmed, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out ulong parsed) && parsed == 0;
        }

        private static byte[] ParseHexBytes(string hex)
        {
            if (string.IsNullOrWhiteSpace(hex) || hex.Equals("<none>", StringComparison.OrdinalIgnoreCase))
            {
                return Array.Empty<byte>();
            }

            var bytes = new List<byte>();
            foreach (string token in hex.Split(new[] { ' ', '\t', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
            {
                if (byte.TryParse(token, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out byte parsed))
                {
                    bytes.Add(parsed);
                }
            }
            return bytes.ToArray();
        }

        private static uint TryParseHexU32(string token)
        {
            if (string.IsNullOrWhiteSpace(token))
            {
                return 0;
            }

            string normalized = token.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? token[2..] : token;
            return uint.TryParse(normalized, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out uint value)
                ? value
                : 0;
        }

        private static ulong TryParseHexU64(string token)
        {
            if (string.IsNullOrWhiteSpace(token))
            {
                return 0;
            }

            string normalized = token.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? token[2..] : token;
            return ulong.TryParse(normalized, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out ulong value)
                ? value
                : 0;
        }

        private static string ReadTokenValue(string text, string prefix)
        {
            if (string.IsNullOrWhiteSpace(text) || string.IsNullOrWhiteSpace(prefix))
            {
                return string.Empty;
            }

            int start = text.IndexOf(prefix, StringComparison.OrdinalIgnoreCase);
            if (start < 0)
            {
                return string.Empty;
            }

            start += prefix.Length;
            int end = start;
            while (end < text.Length && !char.IsWhiteSpace(text[end]))
            {
                end += 1;
            }

            return text[start..end].Trim();
        }

        private static string SliceBetween(string text, string startToken, string endToken)
        {
            if (string.IsNullOrWhiteSpace(text))
            {
                return string.Empty;
            }

            int start = text.IndexOf(startToken, StringComparison.OrdinalIgnoreCase);
            if (start < 0)
            {
                return string.Empty;
            }

            start += startToken.Length;
            int end = text.IndexOf(endToken, start, StringComparison.OrdinalIgnoreCase);
            if (end < 0)
            {
                end = text.Length;
            }

            return text[start..end].Trim();
        }

        private static string ReadRestAfter(string text, string token)
        {
            if (string.IsNullOrWhiteSpace(text))
            {
                return string.Empty;
            }

            int start = text.IndexOf(token, StringComparison.OrdinalIgnoreCase);
            if (start < 0)
            {
                return string.Empty;
            }

            start += token.Length;
            return text[start..].Trim();
        }

        private void SuspectsGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            UpdateDetails(SuspectsGrid.SelectedItem as DirectSyscallEntry);
        }

        private void UpdateDetails(DirectSyscallEntry? entry)
        {
            _selectedEntry = entry;
            if (entry == null)
            {
                OverviewBlock.Text = "<none>";
                _argumentRows.Clear();
                _contextRows.Clear();
                RawBox.Text = string.Empty;
                return;
            }

            OverviewBlock.Text = $"{entry.TimestampUtc:O}\n{entry.SyscallLabel}\nflow: {entry.Actor} -> {entry.Target}\ndetection: {entry.Detection}";
            SetKeyValueRows(_argumentRows, ParseKeyValueRows(entry.Arguments));
            SetKeyValueRows(_contextRows, ParseKeyValueRows(entry.Context));
            RawBox.Text = entry.Raw;
        }

        private void OpenDisassemblyButton_Click(object sender, RoutedEventArgs e)
        {
            if (_selectedEntry == null)
            {
                return;
            }

            DisassemblyDetailWindow.ShowForEntry(
                this,
                _selectedEntry.TimestampUtc,
                _selectedEntry.SyscallLabel,
                _selectedEntry.Actor,
                _selectedEntry.Target,
                _selectedEntry.Addresses,
                _selectedEntry.StubHex,
                _selectedEntry.Disassembly);
        }

        internal static FlowDocument BuildDisassemblyDocument(string disassemblyText)
        {
            var document = new FlowDocument
            {
                FontFamily = new FontFamily("Consolas"),
                FontSize = 12,
                PagePadding = new Thickness(6, 4, 6, 4)
            };

            string text = string.IsNullOrWhiteSpace(disassemblyText) ? "unavailable" : disassemblyText;
            foreach (string line in text.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None))
            {
                var paragraph = new Paragraph { Margin = new Thickness(0) };
                AppendDisassemblyLine(paragraph, line);
                document.Blocks.Add(paragraph);
            }

            return document;
        }

        private static void AppendDisassemblyLine(Paragraph paragraph, string line)
        {
            if (string.IsNullOrWhiteSpace(line))
            {
                paragraph.Inlines.Add(new Run(string.Empty));
                return;
            }

            if (line.StartsWith("hint:", StringComparison.OrdinalIgnoreCase))
            {
                paragraph.Inlines.Add(new Run(line) { Foreground = new SolidColorBrush(Color.FromRgb(0xA6, 0xB0, 0xBA)) });
                return;
            }

            if (line.StartsWith("summary:", StringComparison.OrdinalIgnoreCase))
            {
                paragraph.Inlines.Add(new Run("summary: ") { Foreground = new SolidColorBrush(Color.FromRgb(0x7D, 0xA7, 0xD8)) });
                paragraph.Inlines.Add(new Run(line["summary: ".Length..]) { Foreground = new SolidColorBrush(Color.FromRgb(0xD8, 0xDD, 0xE6)) });
                return;
            }

            if (line.StartsWith("len=", StringComparison.OrdinalIgnoreCase))
            {
                paragraph.Inlines.Add(new Run(line) { Foreground = new SolidColorBrush(Color.FromRgb(0xA6, 0xB0, 0xBA)) });
                return;
            }

            int colon = line.IndexOf(':');
            if (colon <= 0 || !LooksLikeAddress(line[..colon]))
            {
                paragraph.Inlines.Add(new Run(line) { Foreground = new SolidColorBrush(Color.FromRgb(0xD8, 0xDD, 0xE6)) });
                return;
            }

            string address = line[..(colon + 1)];
            paragraph.Inlines.Add(new Run(address + " ") { Foreground = new SolidColorBrush(Color.FromRgb(0x7D, 0xA7, 0xD8)) });

            string rhs = line[(colon + 1)..].TrimStart();
            string[] tokens = rhs.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
            int byteCount = 0;
            while (byteCount < tokens.Length && IsHexByte(tokens[byteCount]))
            {
                byteCount += 1;
            }

            if (byteCount > 0)
            {
                string bytes = string.Join(" ", tokens.Take(byteCount));
                paragraph.Inlines.Add(new Run(bytes.PadRight(24) + " ") { Foreground = new SolidColorBrush(Color.FromRgb(0xB5, 0xC0, 0xCC)) });
            }

            string mnemonic = string.Join(" ", tokens.Skip(byteCount));
            if (mnemonic.Length == 0)
            {
                return;
            }

            foreach (string token in mnemonic.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries))
            {
                string clean = token.Trim(',', ';', '[', ']', '(', ')');
                Brush brush = new SolidColorBrush(Color.FromRgb(0xD8, 0xDD, 0xE6));
                if (IsMnemonicToken(clean))
                {
                    brush = new SolidColorBrush(Color.FromRgb(0xE5, 0xA9, 0x6B));
                }
                else if (IsRegisterToken(clean))
                {
                    brush = new SolidColorBrush(Color.FromRgb(0x7D, 0xC4, 0xE8));
                }
                else if (clean.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                {
                    brush = new SolidColorBrush(Color.FromRgb(0xA4, 0xD2, 0x9A));
                }

                paragraph.Inlines.Add(new Run(token + " ") { Foreground = brush });
            }
        }

        private static bool LooksLikeAddress(string token)
        {
            return token.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ||
                   token.StartsWith("+0x", StringComparison.OrdinalIgnoreCase) ||
                   token.StartsWith("-0x", StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsHexByte(string token)
        {
            return token.Length == 2 &&
                   byte.TryParse(token, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out _);
        }

        private static bool IsMnemonicToken(string token)
        {
            string value = token.ToLowerInvariant();
            return value is "mov" or "syscall" or "ret" or "jmp" or "lea" or "sub" or "add" or "db" or "int3" or "nop" or "qword" or "ptr" or "short";
        }

        private static bool IsRegisterToken(string token)
        {
            string value = token.ToLowerInvariant();
            return value is "rax" or "eax" or "rbx" or "ebx" or "rcx" or "ecx" or "rdx" or "edx" or
                "rsi" or "rdi" or "r8" or "r9" or "r10" or "r11" or "r12" or "r13" or "r14" or "r15" or
                "rsp" or "rbp" or "rip" or "eflags" or "dr0" or "dr1" or "dr2" or "dr3" or "dr6" or "dr7";
        }

        private static void SetKeyValueRows(ObservableCollection<KeyValueRow> destination, IReadOnlyList<KeyValueRow> rows)
        {
            destination.Clear();
            foreach (KeyValueRow row in rows)
            {
                destination.Add(row);
            }
        }

        private static IReadOnlyList<KeyValueRow> ParseKeyValueRows(string text)
        {
            if (string.IsNullOrWhiteSpace(text))
            {
                return Array.Empty<KeyValueRow>();
            }

            var list = new List<KeyValueRow>();
            string[] pairs = text.Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries);
            foreach (string pair in pairs)
            {
                string item = pair.Trim();
                if (item.Length == 0)
                {
                    continue;
                }

                int idx = item.IndexOf('=');
                if (idx <= 0)
                {
                    list.Add(new KeyValueRow { Key = "Value", Value = item });
                    continue;
                }

                string key = item[..idx].Trim();
                string value = item[(idx + 1)..].Trim();
                list.Add(new KeyValueRow
                {
                    Key = key.Length == 0 ? "Field" : key,
                    Value = value
                });
            }

            return list;
        }

        private void TitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            if (e.LeftButton != MouseButtonState.Pressed)
            {
                return;
            }

            if (e.ClickCount >= 2)
            {
                WindowState = WindowState == WindowState.Maximized
                    ? WindowState.Normal
                    : WindowState.Maximized;
                return;
            }

            try
            {
                DragMove();
            }
            catch
            {
            }
        }

        private void WindowMinimize_Click(object sender, RoutedEventArgs e)
        {
            WindowState = WindowState.Minimized;
        }

        private void WindowMaximize_Click(object sender, RoutedEventArgs e)
        {
            WindowState = WindowState == WindowState.Maximized
                ? WindowState.Normal
                : WindowState.Maximized;
        }

        private void WindowClose_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }

        private sealed class DirectSyscallEntry
        {
            public DateTime TimestampUtc { get; set; }
            public string Detection { get; set; } = "";
            public string Actor { get; set; } = "";
            public string Target { get; set; } = "";
            public string TargetObject { get; set; } = "";
            public string SyscallName { get; set; } = "";
            public string SyscallLabel { get; set; } = "";
            public string ActorTargetFlow => $"{Actor} -> {Target}";
            public string DetectionSummary => $"{Detection} | {ActorTargetFlow}";
            public string Arguments { get; set; } = "";
            public string Context { get; set; } = "";
            public string Addresses { get; set; } = "";
            public string StubHex { get; set; } = "";
            public string Disassembly { get; set; } = "";
            public string Raw { get; set; } = "";

            public DirectSyscallEntry Clone()
            {
                return new DirectSyscallEntry
                {
                    TimestampUtc = TimestampUtc,
                    Detection = Detection,
                    Actor = Actor,
                    Target = Target,
                    TargetObject = TargetObject,
                    SyscallName = SyscallName,
                    SyscallLabel = SyscallLabel,
                    Arguments = Arguments,
                    Context = Context,
                    Addresses = Addresses,
                    StubHex = StubHex,
                    Disassembly = Disassembly,
                    Raw = Raw
                };
            }
        }

        private sealed class KeyValueRow
        {
            public string Key { get; set; } = "";
            public string Value { get; set; } = "";
        }
    }
}
