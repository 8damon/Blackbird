using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.Text;
using System.Windows;

namespace SleepwalkerInterface
{
    public partial class HandleEvidenceWindow : Window
    {
        private readonly ObservableCollection<InspectorFieldNode> _fieldNodes = new();
        private string _rawText = string.Empty;

        private HandleEvidenceWindow(string context, IoctlParsedEvent evidence)
        {
            InitializeComponent();
            WindowThemeHelper.ApplyDarkTitleBar(this);

            Title = string.IsNullOrWhiteSpace(context) ? "Handle Evidence" : $"Handle Evidence - {context}";
            HeaderBlock.Text = string.IsNullOrWhiteSpace(context) ? "Handle Evidence" : context.Trim();
            SummaryBlock.Text = BuildSummaryText(evidence);

            FieldsTreeView.ItemsSource = _fieldNodes;
            BuildTree(evidence);
        }

        internal static void ShowForEvidence(Window? owner, string context, IoctlParsedEvent evidence)
        {
            var window = new HandleEvidenceWindow(context, evidence);
            if (owner != null && !ReferenceEquals(owner, window))
            {
                window.Owner = owner;
            }

            window.Show();
            window.Activate();
        }

        private void BuildTree(IoctlParsedEvent evidence)
        {
            _fieldNodes.Clear();
            string syscallLabel = EventDetailFormatting.BuildDirectSyscallLabel(
                evidence.DesiredAccess,
                evidence.HandleFlags,
                evidence.DeepSample,
                (int)evidence.DeepSampleSize);
            string analystSummary = EventDetailFormatting.BuildDirectSyscallSummary(
                evidence.CallerPid.ToString(CultureInfo.InvariantCulture),
                evidence.TargetPid.ToString(CultureInfo.InvariantCulture),
                evidence.DesiredAccess,
                evidence.HandleFlags,
                evidence.DeepSample,
                (int)evidence.DeepSampleSize,
                evidence.OriginPath);
            _rawText =
                $"callerPid={evidence.CallerPid} targetPid={evidence.TargetPid} class={DescribeHandleClass(evidence.HandleClass)}{Environment.NewLine}" +
                $"syscall={syscallLabel}{Environment.NewLine}" +
                $"summary={analystSummary}{Environment.NewLine}" +
                $"desiredAccess=0x{evidence.DesiredAccess:X8} handleFlags=0x{evidence.HandleFlags:X8}{Environment.NewLine}" +
                $"originAddress=0x{evidence.OriginAddress:X} originProtect=0x{evidence.OriginProtect:X8}{Environment.NewLine}" +
                $"deepAllocationBase=0x{evidence.DeepAllocationBase:X} deepRegionSize=0x{evidence.DeepRegionSize:X}{Environment.NewLine}" +
                $"captureFlags=0x{evidence.CaptureFlags:X8} ({DescribeCaptureFlags(evidence.CaptureFlags)})";

            InspectorFieldNode AddSection(string name, bool expanded = true)
            {
                var node = new InspectorFieldNode
                {
                    Name = name,
                    Kind = "section",
                    IsExpanded = expanded
                };
                _fieldNodes.Add(node);
                return node;
            }

            static void AddPair(InspectorFieldNode parent, string name, string value)
            {
                if (string.IsNullOrWhiteSpace(value))
                {
                    return;
                }

                parent.Children.Add(new InspectorFieldNode
                {
                    Name = name,
                    Value = value.Trim(),
                    Kind = "pair"
                });
            }

            static void AddLine(InspectorFieldNode parent, string value, string kind = "line")
            {
                if (string.IsNullOrWhiteSpace(value))
                {
                    return;
                }

                parent.Children.Add(new InspectorFieldNode
                {
                    Value = value,
                    Kind = kind
                });
            }

            InspectorFieldNode frame = AddSection("Frame");
            AddPair(frame, "Summary", analystSummary);
            AddPair(frame, "Sequence", evidence.Sequence.ToString(CultureInfo.InvariantCulture));
            AddPair(frame, "Stream Mask", $"0x{evidence.StreamMask:X8}");
            AddPair(frame, "Class", DescribeHandleClass(evidence.HandleClass));
            AddPair(frame, "Syscall", syscallLabel);
            AddPair(frame, "Caller PID", evidence.CallerPid.ToString(CultureInfo.InvariantCulture));
            AddPair(frame, "Target PID", evidence.TargetPid.ToString(CultureInfo.InvariantCulture));
            AddPair(frame, "Desired Access", $"0x{evidence.DesiredAccess:X8} ({EventDetailFormatting.DescribeHandleAccess(evidence.DesiredAccess)})");
            AddPair(frame, "Handle Flags", $"0x{evidence.HandleFlags:X8} ({EventDetailFormatting.DescribeHandleFlags(evidence.HandleFlags)})");
            AddPair(frame, "Capture Flags", $"0x{evidence.CaptureFlags:X8} ({DescribeCaptureFlags(evidence.CaptureFlags)})");

            InspectorFieldNode origin = AddSection("Origin", false);
            AddPair(origin, "Address", $"0x{evidence.OriginAddress:X}");
            AddPair(origin, "Protect", $"0x{evidence.OriginProtect:X8} ({EventDetailFormatting.DescribeMemoryProtection(evidence.OriginProtect)})");
            AddPair(origin, "Path", EventDetailsParsing.FallbackText(evidence.OriginPath));
            AddPair(origin, "OpenProcess", $"0x{unchecked((uint)evidence.StatusOpenProcess):X8}");
            AddPair(origin, "BasicInfo", $"0x{unchecked((uint)evidence.StatusBasicInfo):X8}");
            AddPair(origin, "SectionName", $"0x{unchecked((uint)evidence.StatusSectionName):X8}");

            InspectorFieldNode region = AddSection("Region", false);
            AddPair(region, "Allocation Base", $"0x{evidence.DeepAllocationBase:X}");
            AddPair(region, "Region Size", $"0x{evidence.DeepRegionSize:X}");
            AddPair(region, "Protect", $"0x{evidence.DeepRegionProtect:X8} ({EventDetailFormatting.DescribeMemoryProtection(evidence.DeepRegionProtect)})");
            AddPair(region, "State", $"0x{evidence.DeepRegionState:X8} ({EventDetailFormatting.DescribeMemoryState(evidence.DeepRegionState)})");
            AddPair(region, "Type", $"0x{evidence.DeepRegionType:X8} ({EventDetailFormatting.DescribeMemoryType(evidence.DeepRegionType)})");
            AddPair(region, "Sample Size", evidence.DeepSampleSize.ToString(CultureInfo.InvariantCulture));
            AddPair(region, "Stack Snapshot Address", $"0x{evidence.StackSnapshotAddress:X}");
            AddPair(region, "Stack Snapshot Size", evidence.StackSnapshotSize.ToString(CultureInfo.InvariantCulture));

            InspectorFieldNode registers = AddSection("Registers", false);
            AddRegister(registers, "RAX", evidence.RegRax);
            AddRegister(registers, "RBX", evidence.RegRbx);
            AddRegister(registers, "RCX", evidence.RegRcx);
            AddRegister(registers, "RDX", evidence.RegRdx);
            AddRegister(registers, "RSI", evidence.RegRsi);
            AddRegister(registers, "RDI", evidence.RegRdi);
            AddRegister(registers, "RBP", evidence.RegRbp);
            AddRegister(registers, "RSP", evidence.RegRsp);
            AddRegister(registers, "R8", evidence.RegR8);
            AddRegister(registers, "R9", evidence.RegR9);
            AddRegister(registers, "R10", evidence.RegR10);
            AddRegister(registers, "R11", evidence.RegR11);
            AddRegister(registers, "R12", evidence.RegR12);
            AddRegister(registers, "R13", evidence.RegR13);
            AddRegister(registers, "R14", evidence.RegR14);
            AddRegister(registers, "R15", evidence.RegR15);
            AddRegister(registers, "RIP", evidence.RegRip);
            AddRegister(registers, "EFLAGS", evidence.RegEFlags);
            AddRegister(registers, "DR0", evidence.RegDr0);
            AddRegister(registers, "DR1", evidence.RegDr1);
            AddRegister(registers, "DR2", evidence.RegDr2);
            AddRegister(registers, "DR3", evidence.RegDr3);
            AddRegister(registers, "DR6", evidence.RegDr6);
            AddRegister(registers, "DR7", evidence.RegDr7);

            InspectorFieldNode capturedStack = AddSection("Captured Stack");
            AddFrames(capturedStack, evidence.Frames, evidence.FrameCount, "frames");
            AddFrames(capturedStack, evidence.FullFrames, evidence.FullFrameCount, "fullFrames");
            AddFrames(capturedStack, evidence.ThreadFrames, evidence.ThreadFrameCount, "threadFrames");
            if (capturedStack.Children.Count == 0)
            {
                AddLine(capturedStack, "No captured stack frames available.", "note");
            }

            InspectorFieldNode disassembly = AddSection("Disassembly");
            foreach (string line in SplitLines(EventDetailFormatting.FormatSampleDisassembly(
                         evidence.DeepSample,
                         (int)evidence.DeepSampleSize,
                         evidence.OriginAddress,
                         evidence.OriginPath,
                         evidence.DeepAllocationBase,
                         evidence.DeepRegionSize,
                         evidence.DeepRegionProtect,
                         evidence.DeepRegionState,
                         evidence.DeepRegionType)))
            {
                AddLine(disassembly, line, line.StartsWith("summary:", StringComparison.OrdinalIgnoreCase) ? "note" : "line");
            }

            InspectorFieldNode snapshot = AddSection("Stack Snapshot", false);
            foreach (string line in SplitLines(
                         $"stackSnapshotAddress=0x{evidence.StackSnapshotAddress:X}{Environment.NewLine}" +
                         $"stackSnapshotSize={evidence.StackSnapshotSize}{Environment.NewLine}" +
                         $"stackSnapshot={EventDetailFormatting.FormatSampleHex(evidence.StackSnapshot, (int)evidence.StackSnapshotSize)}"))
            {
                AddLine(snapshot, line);
            }

            InspectorFieldNode raw = AddSection("Raw", false);
            foreach (string line in SplitLines(_rawText))
            {
                AddLine(raw, line);
            }
        }

        private static void AddRegister(InspectorFieldNode parent, string name, ulong value)
        {
            parent.Children.Add(new InspectorFieldNode
            {
                Name = name,
                Value = value == 0 ? "-" : $"0x{value:X}",
                Kind = "pair"
            });
        }

        private static void AddFrames(InspectorFieldNode parent, ulong[]? frames, uint count, string label)
        {
            if (frames == null || frames.Length == 0 || count == 0)
            {
                return;
            }

            int safeCount = Math.Min(frames.Length, (int)count);
            for (int i = 0; i < safeCount; i += 1)
            {
                if (frames[i] == 0)
                {
                    continue;
                }

                parent.Children.Add(new InspectorFieldNode
                {
                    Name = $"{label}[{i}]",
                    Value = $"0x{frames[i]:X}",
                    Kind = "pair"
                });
            }
        }

        private static IEnumerable<string> SplitLines(string text)
        {
            if (string.IsNullOrWhiteSpace(text))
            {
                yield return "unavailable";
                yield break;
            }

            foreach (string line in text.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None))
            {
                yield return line.Length == 0 ? " " : line;
            }
        }

        private static string DescribeHandleClass(uint handleClass)
        {
            return handleClass switch
            {
                1 => "LEGITIMATE-SYSCALL",
                2 => "DIRECT-SYSCALL-SUSPECT",
                _ => $"CLASS-{handleClass}"
            };
        }

        private static string DescribeCaptureFlags(uint captureFlags)
        {
            var labels = new Collection<string>();
            if ((captureFlags & 0x00000001u) != 0)
            {
                labels.Add("CONTEXT");
            }
            if ((captureFlags & 0x00000002u) != 0)
            {
                labels.Add("DEBUG_REGS");
            }
            if ((captureFlags & 0x00000004u) != 0)
            {
                labels.Add("FULL_FRAMES");
            }
            if ((captureFlags & 0x00000008u) != 0)
            {
                labels.Add("STACK_SNAPSHOT");
            }

            return labels.Count == 0 ? "NONE" : string.Join("|", labels);
        }

        private static string BuildSummaryText(IoctlParsedEvent evidence)
        {
            string prefix = $"{DescribeHandleClass(evidence.HandleClass)}  caller={evidence.CallerPid}  target={evidence.TargetPid}";
            if (evidence.HandleClass != 2)
            {
                return $"{prefix}  access=0x{evidence.DesiredAccess:X8}";
            }

            string syscallLabel = EventDetailFormatting.BuildDirectSyscallLabel(
                evidence.DesiredAccess,
                evidence.HandleFlags,
                evidence.DeepSample,
                (int)evidence.DeepSampleSize);
            string narrative = EventDetailFormatting.BuildDirectSyscallSummary(
                evidence.CallerPid.ToString(CultureInfo.InvariantCulture),
                evidence.TargetPid.ToString(CultureInfo.InvariantCulture),
                evidence.DesiredAccess,
                evidence.HandleFlags,
                evidence.DeepSample,
                (int)evidence.DeepSampleSize,
                evidence.OriginPath);
            return $"{syscallLabel}  {narrative}";
        }

        private void ExpandAll_Click(object sender, RoutedEventArgs e)
        {
            _ = sender;
            _ = e;
            SetTreeExpansion(_fieldNodes, true);
        }

        private void CollapseAll_Click(object sender, RoutedEventArgs e)
        {
            _ = sender;
            _ = e;
            SetTreeExpansion(_fieldNodes, false);
        }

        private void CopyVisible_Click(object sender, RoutedEventArgs e)
        {
            _ = sender;
            _ = e;
            var sb = new StringBuilder();
            foreach (InspectorFieldNode node in _fieldNodes)
            {
                AppendFieldNode(sb, node, 0);
            }
            Clipboard.SetText(sb.ToString().Trim());
        }

        private void CopyRaw_Click(object sender, RoutedEventArgs e)
        {
            _ = sender;
            _ = e;
            Clipboard.SetText(_rawText);
        }

        private static void AppendFieldNode(StringBuilder sb, InspectorFieldNode node, int depth)
        {
            string indent = new string(' ', depth * 2);
            string label = node.Kind switch
            {
                "section" => node.Name,
                "pair" => $"{node.Name}: {node.Value}",
                _ => node.Value
            };

            sb.Append(indent).AppendLine(label);
            foreach (InspectorFieldNode child in node.Children)
            {
                AppendFieldNode(sb, child, depth + 1);
            }
        }

        private static void SetTreeExpansion(IEnumerable<InspectorFieldNode> nodes, bool isExpanded)
        {
            foreach (InspectorFieldNode node in nodes)
            {
                node.IsExpanded = isExpanded;
                SetTreeExpansion(node.Children, isExpanded);
            }
        }
    }
}
