using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;

namespace BlackbirdInterface
{
    public partial class ThreadStackWindow : Window
    {
        private const string MissingText = "N/A";
        private const int MaxSnapshotHistory = 128;

        public ObservableCollection<StackFrameRow> UserFrames { get; } = new();
        public ObservableCollection<RegisterEntry> GeneralRegs { get; } = new();
        private readonly Dictionary<string, RegisterEntry> _generalRegByName = new(StringComparer.OrdinalIgnoreCase);

        private readonly int _pid;
        private readonly int _tid;
        private string _state;
        private readonly Func<DateTime>? _observationTimeUtcProvider;
        private readonly Func<bool>? _liveCaptureAvailableProvider;
        private readonly Func<int, string>? _threadStateProvider;
        private readonly Action<ThreadStackSessionSnapshot>? _onSnapshotCaptured;
        private readonly DispatcherTimer _refreshTimer;
        private readonly List<ThreadStackSessionSnapshot> _snapshotHistory = new();
        private bool _refreshInFlight;
        private ThreadStackSessionSnapshot? _lastAppliedSnapshot;

        public ThreadStackWindow(int pid, int tid, string state,
                                 IEnumerable<ThreadStackSessionSnapshot>? initialHistory = null,
                                 Action<ThreadStackSessionSnapshot>? onSnapshotCaptured = null,
                                 Func<DateTime>? observationTimeUtcProvider = null,
                                 Func<bool>? liveCaptureAvailableProvider = null,
                                 Func<int, string>? threadStateProvider = null)
        {
            InitializeComponent();
            WindowThemeHelper.WireThemeAwareTitleBar(this);

            _pid = pid;
            _tid = tid;
            _state = state;
            _onSnapshotCaptured = onSnapshotCaptured;
            _observationTimeUtcProvider = observationTimeUtcProvider;
            _liveCaptureAvailableProvider = liveCaptureAvailableProvider;
            _threadStateProvider = threadStateProvider;
            _refreshTimer = new DispatcherTimer(DispatcherPriority.Background) { Interval = TimeSpan.FromSeconds(2) };
            _refreshTimer.Tick += async (_, __) => await RefreshDisplayAsync();

            HeaderBlock.Text = $"Thread {_tid} Stack";
            HeaderStateBlock.Text = string.IsNullOrWhiteSpace(_state) ? $"State: {MissingText}" : $"State: {_state}";
            ApplyStateVisuals(_state);

            UserStackGrid.ItemsSource = UserFrames;
            GeneralRegsList.ItemsSource = GeneralRegs;
            if (initialHistory != null)
            {
                _snapshotHistory.AddRange(initialHistory.Select(x => x.Clone()).OrderBy(x => x.CapturedAtUtc));
            }

            SeedRegisterPlaceholders();
            Loaded += async (_, __) =>
            {
                await RefreshDisplayAsync();
                _refreshTimer.Start();
            };
            Closed += (_, __) => _refreshTimer.Stop();
        }

        private void SeedRegisterPlaceholders()
        {
            GeneralRegs.Clear();
            _generalRegByName.Clear();

            string[] regs = { "RIP", "RSP", "RBP", "RAX", "RBX", "RCX", "RDX", "RSI", "RDI",
                              "R8",  "R9",  "R10", "R11", "R12", "R13", "R14", "R15" };
            foreach (var r in regs)
            {
                var entry = new RegisterEntry(r, MissingText);
                GeneralRegs.Add(entry);
                _generalRegByName[r] = entry;
            }

            EFlagsMetaBlock.Text = MissingText;
            EFlagsDetailBlock.Text = MissingText;
            EFlagsEnglishBlock.Text = MissingText;
            DrxBitsBlock.Text = MissingText;
            StackSpanMetaBlock.Text = MissingText;
            ActiveSpanMetaBlock.Text = MissingText;
            StateMetaBlock.Text = string.IsNullOrWhiteSpace(_state) ? MissingText : _state;
        }

        private void ApplyStateVisuals(string? state)
        {
            Brush brush = GetStateBrush(state);
            HeaderStateBlock.Foreground = brush;
            HeaderStateBlock.FontWeight = FontWeights.SemiBold;
            StateMetaBlock.Foreground = brush;
            StateMetaBlock.FontWeight = FontWeights.SemiBold;
        }

        private static Brush GetStateBrush(string? state)
        {
            string value = (state ?? string.Empty).Trim().ToLowerInvariant();
            if (value is "running" or "ready")
            {
                return ResolveResourceBrush("StatusConnectedBrush", Color.FromRgb(0x5B, 0xD1, 0x71));
            }

            if (value is "wait" or "waiting" or "sleep" or "sleeping")
            {
                return ResolveResourceBrush("StatusWarningBrush", Color.FromRgb(0xE0, 0xC2, 0x6C));
            }

            if (value is "suspended" or "blocked" or "terminated")
            {
                return ResolveResourceBrush("StatusErrorBrush", Color.FromRgb(0xE0, 0x78, 0x78));
            }

            return ResolveResourceBrush("WinMutedTextBrush", Color.FromRgb(0xB0, 0xB0, 0xB0));
        }

        private static Brush ResolveResourceBrush(string key, Color fallback)
        {
            if (Application.Current?.TryFindResource(key) is Brush brush)
            {
                return brush;
            }

            var created = new SolidColorBrush(fallback);
            created.Freeze();
            return created;
        }

        private void Root_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            WindowChromeBehavior.HandleRootDragMove(this, e);
        }

        private async Task RefreshDisplayAsync()
        {
            if (_refreshInFlight)
            {
                return;
            }

            _refreshInFlight = true;
            try
            {
                string currentState = RefreshCurrentState();
                DateTime observedUtc = GetObservedUtc();
                bool liveCaptureAvailable = _liveCaptureAvailableProvider?.Invoke() ?? true;
                bool preferLive = ShouldResolveLive(observedUtc, liveCaptureAvailable);
                ThreadStackResolveResult? liveResult = null;

                if (preferLive)
                {
                    NoteBlock.Text = "Resolving stack...";
                    liveResult = await Task.Run(() => ThreadStackResolver.Resolve(_pid, _tid, currentState));
                    if (HasResolvedStackData(liveResult))
                    {
                        ThreadStackSessionSnapshot snapshot = CreateSnapshot(DateTime.UtcNow, liveResult);
                        _snapshotHistory.Add(snapshot);
                        if (_snapshotHistory.Count > MaxSnapshotHistory)
                        {
                            _snapshotHistory.RemoveRange(0, _snapshotHistory.Count - MaxSnapshotHistory);
                        }

                        _onSnapshotCaptured?.Invoke(snapshot.Clone());
                        ApplySnapshot(snapshot, $"Live | {snapshot.CapturedAtUtc:HH:mm:ss.fff}");
                        return;
                    }
                }

                ThreadStackSessionSnapshot? historical = FindHistoricalSnapshot(observedUtc);
                if (historical != null)
                {
                    ApplySnapshot(historical, $"Historical | {historical.CapturedAtUtc:HH:mm:ss.fff}");
                    return;
                }

                if (_lastAppliedSnapshot != null)
                {
                    NoteBlock.Text =
                        $"Stale | {_lastAppliedSnapshot.CapturedAtUtc:HH:mm:ss.fff} | no newer stack available";
                    return;
                }

                string noDataReason =
                    liveCaptureAvailable
                        ? "No captured stack for the selected time."
                        : "Thread is no longer live and no captured stack exists for the selected time.";
                if (!string.IsNullOrWhiteSpace(liveResult?.Note))
                {
                    noDataReason = liveResult.Note;
                }
                ApplyNoDataState(noDataReason);
            }
            catch
            {
                if (_lastAppliedSnapshot != null)
                {
                    NoteBlock.Text = $"Stale | {_lastAppliedSnapshot.CapturedAtUtc:HH:mm:ss.fff} | refresh failed";
                }
                else
                {
                    ApplyNoDataState("Failed to resolve stack.");
                }
            }
            finally
            {
                _refreshInFlight = false;
            }
        }

        private DateTime GetObservedUtc() => _observationTimeUtcProvider?.Invoke() ?? DateTime.UtcNow;

        private string RefreshCurrentState()
        {
            string? current = _threadStateProvider?.Invoke(_tid);
            if (!string.IsNullOrWhiteSpace(current))
            {
                _state = current.Trim();
            }

            HeaderStateBlock.Text = string.IsNullOrWhiteSpace(_state) ? $"State: {MissingText}" : $"State: {_state}";
            ApplyStateVisuals(_state);
            return _state;
        }

        private bool ShouldResolveLive(DateTime observedUtc, bool liveCaptureAvailable)
        {
            if (!liveCaptureAvailable)
            {
                return false;
            }

            if (_snapshotHistory.Count == 0)
            {
                return true;
            }

            DateTime latestCaptureUtc = _snapshotHistory[^1].CapturedAtUtc;
            return observedUtc >= latestCaptureUtc.AddMilliseconds(-750);
        }

        private ThreadStackSessionSnapshot? FindHistoricalSnapshot(DateTime observedUtc)
        {
            return _snapshotHistory.Where(x => x.CapturedAtUtc <= observedUtc)
                .OrderByDescending(x => x.CapturedAtUtc)
                .FirstOrDefault();
        }

        private static bool HasResolvedStackData(ThreadStackResolveResult result)
        {
            return result.Frames.Count > 0 || result.StackPointer != 0 || result.TebAddress != 0 ||
                   result.ContextSnapshot != null;
        }

        private ThreadStackSessionSnapshot CreateSnapshot(DateTime capturedAtUtc, ThreadStackResolveResult result)
        {
            return new ThreadStackSessionSnapshot { CapturedAtUtc = capturedAtUtc,
                                                    TebAddress = result.TebAddress,
                                                    StackBase = result.StackBase,
                                                    StackTop = result.StackTop,
                                                    TebFlags = result.TebFlags,
                                                    StackPointer = result.StackPointer,
                                                    ContextSnapshot = CloneContextSnapshot(result.ContextSnapshot),
                                                    Frames = result.Frames.Select(CloneFrame).ToList() };
        }

        private void ApplySnapshot(ThreadStackSessionSnapshot snapshot, string note)
        {
            _lastAppliedSnapshot = snapshot.Clone();
            HideNoDataOverlay();
            ResetHeaderMetadata();

            PidBlock.Text = _pid.ToString();
            TidBlock.Text = _tid.ToString();
            TebBlock.Text = snapshot.TebAddress == 0 ? MissingText : $"0x{snapshot.TebAddress:X}";
            StackBaseMetaBlock.Text = snapshot.StackBase == 0 ? MissingText : $"0x{snapshot.StackBase:X}";
            StackTopMetaBlock.Text = snapshot.StackTop == 0 ? MissingText : $"0x{snapshot.StackTop:X}";
            RspMetaBlock.Text = snapshot.StackPointer == 0 ? MissingText : $"0x{snapshot.StackPointer:X}";
            TebFlagsMetaBlock.Text = snapshot.TebFlags.HasValue ? $"0x{snapshot.TebFlags.Value:X4}" : MissingText;
            StateMetaBlock.Text = string.IsNullOrWhiteSpace(_state) ? MissingText : _state;

            ulong stackSpan = snapshot.StackBase > snapshot.StackTop ? snapshot.StackBase - snapshot.StackTop : 0UL;
            StackSpanMetaBlock.Text = stackSpan == 0 ? MissingText : $"0x{stackSpan:X} ({stackSpan} B)";
            ActiveSpanMetaBlock.Text = MissingText;

            UserFrames.Clear();
            foreach (StackFrameRow frame in snapshot.Frames.Select(CloneFrame))
            {
                UserFrames.Add(frame);
            }

            ComputeFrameSpans(snapshot.StackBase, snapshot.StackTop);
            for (int i = 0; i < UserFrames.Count; i += 1)
            {
                UserFrames[i].IsCurrent = i == 0;
            }

            ulong rip = UserFrames.Select(x => x.InstructionPointerRaw).FirstOrDefault(v => v != 0);
            RipMetaBlock.Text = rip == 0 ? MissingText : $"0x{rip:X}";
            SetReg("RIP", rip == 0 ? (ulong?)null : rip);
            SetReg("RSP", snapshot.StackPointer == 0 ? (ulong?)null : snapshot.StackPointer);
            SetReg("RBP", UserFrames.Select(x => x.FramePointerRaw).FirstOrDefault(v => v != 0));
            ApplyResolvedContext(snapshot.ContextSnapshot);

            NoteBlock.Text = $"{note} | {UserFrames.Count} user frame(s)";
        }

        private void ApplyNoDataState(string reason)
        {
            ResetHeaderMetadata();
            PidBlock.Text = _pid.ToString();
            TidBlock.Text = _tid.ToString();
            StateMetaBlock.Text = string.IsNullOrWhiteSpace(_state) ? MissingText : _state;
            SeedRegisterPlaceholders();
            UserFrames.Clear();
            ShowNoDataOverlay(reason);
            NoteBlock.Text = reason;
        }

        private void ResetHeaderMetadata()
        {
            TebBlock.Text = MissingText;
            StackBaseMetaBlock.Text = MissingText;
            StackTopMetaBlock.Text = MissingText;
            RipMetaBlock.Text = MissingText;
            RspMetaBlock.Text = MissingText;
            TebFlagsMetaBlock.Text = MissingText;
            EFlagsMetaBlock.Text = MissingText;
            EFlagsDetailBlock.Text = MissingText;
            EFlagsEnglishBlock.Text = MissingText;
            DrxBitsBlock.Text = MissingText;
            StackSpanMetaBlock.Text = MissingText;
            ActiveSpanMetaBlock.Text = MissingText;
        }

        private void ShowNoDataOverlay(string message)
        {
            if (StackNoDataOverlay != null)
            {
                StackNoDataOverlay.Visibility = Visibility.Visible;
            }

            if (StackNoDataMessageBlock != null)
            {
                StackNoDataMessageBlock.Text = message;
            }
        }

        private void HideNoDataOverlay()
        {
            if (StackNoDataOverlay != null)
            {
                StackNoDataOverlay.Visibility = Visibility.Collapsed;
            }
        }

        private void SetReg(string name, ulong? value)
        {
            if (_generalRegByName.TryGetValue(name, out var entry))
            {
                entry.ValueText = value.HasValue ? $"0x{value.Value:X}" : MissingText;
            }
        }

        private void ApplyResolvedContext(ThreadContextSnapshot? snapshot)
        {
            if (snapshot == null)
            {
                return;
            }

            (string Name, ulong Value)[] regs = { ("RAX", snapshot.Rax), ("RBX", snapshot.Rbx), ("RCX", snapshot.Rcx),
                                                  ("RDX", snapshot.Rdx), ("RSI", snapshot.Rsi), ("RDI", snapshot.Rdi),
                                                  ("R8", snapshot.R8),   ("R9", snapshot.R9),   ("R10", snapshot.R10),
                                                  ("R11", snapshot.R11), ("R12", snapshot.R12), ("R13", snapshot.R13),
                                                  ("R14", snapshot.R14), ("R15", snapshot.R15) };
            foreach (var reg in regs)
            {
                SetReg(reg.Name, reg.Value);
            }

            EFlagsMetaBlock.Text = $"0x{snapshot.EFlags:X8}";
            EFlagsDetailBlock.Text = DecodeEFlags(snapshot.EFlags);
            EFlagsEnglishBlock.Text = DescribeEFlagsEnglish(snapshot.EFlags);
            DrxBitsBlock.Text = BuildDrxBitView(snapshot);
        }

        private static string DecodeEFlags(uint eflags)
        {
            string[] bits = { ((eflags & (1u << 0)) != 0) ? "CF" : "", ((eflags & (1u << 2)) != 0) ? "PF" : "",
                              ((eflags & (1u << 4)) != 0) ? "AF" : "", ((eflags & (1u << 6)) != 0) ? "ZF" : "",
                              ((eflags & (1u << 7)) != 0) ? "SF" : "", ((eflags & (1u << 8)) != 0) ? "TF" : "",
                              ((eflags & (1u << 9)) != 0) ? "IF" : "", ((eflags & (1u << 10)) != 0) ? "DF" : "",
                              ((eflags & (1u << 11)) != 0) ? "OF" : "" };

            string joined = string.Join(" ", bits.Where(x => !string.IsNullOrWhiteSpace(x)));
            if (string.IsNullOrWhiteSpace(joined))
            {
                joined = "none";
            }

            uint iopl = (eflags >> 12) & 0x3u;
            return $"{joined}  IOPL={iopl}";
        }

        private static string DescribeEFlagsEnglish(uint eflags)
        {
            var items = new List<string>();
            items.Add(((eflags & (1u << 6)) != 0) ? "Zero result" : "Non-zero result");
            items.Add(((eflags & (1u << 7)) != 0) ? "Negative sign" : "Positive sign");
            items.Add(((eflags & (1u << 0)) != 0) ? "Carry occurred" : "No carry");
            items.Add(((eflags & (1u << 11)) != 0) ? "Signed overflow" : "No signed overflow");
            items.Add(((eflags & (1u << 9)) != 0) ? "Interrupts enabled" : "Interrupts disabled");
            items.Add(((eflags & (1u << 10)) != 0) ? "Direction down" : "Direction up");
            uint iopl = (eflags >> 12) & 0x3u;
            items.Add($"I/O privilege level {iopl}");
            return string.Join(" | ", items);
        }

        private static string BuildDrxBitView(ThreadContextSnapshot snapshot)
        {
            string drLine0 = $"DR0 {Hex64(snapshot.Dr0)}   DR1 {Hex64(snapshot.Dr1)}";
            string drLine1 = $"DR2 {Hex64(snapshot.Dr2)}   DR3 {Hex64(snapshot.Dr3)}";
            string drLine2 = $"DR6 {Hex64(snapshot.Dr6)}   DR7 {Hex64(snapshot.Dr7)}";
            string dr6Bits =
                $"DR6 bits: B0={Bit(snapshot.Dr6, 0)} B1={Bit(snapshot.Dr6, 1)} B2={Bit(snapshot.Dr6, 2)} B3={Bit(snapshot.Dr6, 3)} BD={Bit(snapshot.Dr6, 13)} BS={Bit(snapshot.Dr6, 14)} BT={Bit(snapshot.Dr6, 15)}";
            string dr7Bits =
                $"DR7 bits: L0={Bit(snapshot.Dr7, 0)} G0={Bit(snapshot.Dr7, 1)} L1={Bit(snapshot.Dr7, 2)} G1={Bit(snapshot.Dr7, 3)} L2={Bit(snapshot.Dr7, 4)} G2={Bit(snapshot.Dr7, 5)} L3={Bit(snapshot.Dr7, 6)} G3={Bit(snapshot.Dr7, 7)}";

            return string.Join(Environment.NewLine, drLine0, drLine1, drLine2, dr6Bits, dr7Bits);
        }

        private static string Hex64(ulong value)
        {
            return $"0x{value:X16}";
        }

        private static int Bit(ulong value, int bit)
        {
            return ((value >> bit) & 1UL) != 0 ? 1 : 0;
        }

        private void ComputeFrameSpans(ulong stackBase, ulong stackTop)
        {
            if (UserFrames.Count == 0)
            {
                return;
            }

            var points = UserFrames.Select(x => x.FramePointerRaw)
                             .Where(v => v >= stackTop && v <= stackBase)
                             .Distinct()
                             .OrderByDescending(v => v)
                             .ToList();

            if (points.Count == 0)
            {
                foreach (var frame in UserFrames)
                {
                    frame.FrameSpanBytes = 0;
                }
                return;
            }

            var spansByPointer = new Dictionary<ulong, long>();
            for (int i = 0; i < points.Count; i += 1)
            {
                ulong hi = points[i];
                if (i + 1 >= points.Count)
                {
                    spansByPointer[hi] = 0;
                    continue;
                }

                ulong lo = points[i + 1];
                long span = hi > lo ? (long)(hi - lo) : 0L;
                spansByPointer[hi] = span;
            }

            foreach (var frame in UserFrames)
            {
                frame.FrameSpanBytes = spansByPointer.TryGetValue(frame.FramePointerRaw, out long span) ? span : 0L;
            }
        }

        private void Close_Click(object sender, RoutedEventArgs e) => Close();

        private static StackFrameRow CloneFrame(StackFrameRow frame)
        {
            return new StackFrameRow { Index = frame.Index,
                                       Address = frame.Address,
                                       Module = frame.Module,
                                       Symbol = frame.Symbol,
                                       InstructionPointerRaw = frame.InstructionPointerRaw,
                                       FramePointerRaw = frame.FramePointerRaw,
                                       FrameSpanBytes = frame.FrameSpanBytes,
                                       IsCurrent = frame.IsCurrent };
        }

        private static ThreadContextSnapshot? CloneContextSnapshot(ThreadContextSnapshot? snapshot) =>
            snapshot == null ? null
                             : new ThreadStackSessionSnapshot { ContextSnapshot = snapshot }.Clone().ContextSnapshot;
    }

    public sealed class RegisterEntry : INotifyPropertyChanged
    {
        public string Name { get; }
        private string _valueText;

        public string ValueText
        {
            get => _valueText;
            set {
                if (string.Equals(_valueText, value, StringComparison.Ordinal))
                {
                    return;
                }

                _valueText = value;
                OnPropertyChanged();
            }
        }

        public RegisterEntry(string name, string valueText)
        {
            Name = name;
            _valueText = valueText;
        }

        public event PropertyChangedEventHandler? PropertyChanged;
        private void OnPropertyChanged([CallerMemberName] string? propertyName = null) =>
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }

}
