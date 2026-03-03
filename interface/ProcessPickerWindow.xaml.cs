using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;

namespace SleepwalkerInterface
{
    public partial class ProcessPickerWindow : Window
    {
        private readonly List<ProcessItem> _all = new();
        private readonly ObservableCollection<ProcessItem> _view = new();
        private readonly ObservableCollection<ProcessFilterRule> _rules = new();
        private readonly Dictionary<int, (TimeSpan cpu, DateTime ts)> _cpuBaseline = new();
        private readonly Dictionary<string, bool> _signatureCache = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, ProcessPathMetadata> _pathMetadataCache = new(StringComparer.OrdinalIgnoreCase);
        private readonly DispatcherTimer _refreshTimer;
        private bool _isReady;

        public int SelectedPid { get; private set; }

        public ProcessPickerWindow()
        {
            InitializeComponent();
            WindowThemeHelper.ApplyDarkTitleBar(this);

            ProcessGrid.ItemsSource = _view;
            RulesGrid.ItemsSource = _rules;

            _refreshTimer = new DispatcherTimer(DispatcherPriority.Background)
            {
                Interval = TimeSpan.FromSeconds(2)
            };
            _refreshTimer.Tick += (_, __) => RefreshList();

            Loaded += (_, __) =>
            {
                RefreshList();
                _refreshTimer.Start();
            };
            Closed += (_, __) => _refreshTimer.Stop();

            _isReady = true;
        }

        private void Refresh_Click(object sender, RoutedEventArgs e) => RefreshList();

        private void QuickSearchBox_TextChanged(object sender, TextChangedEventArgs e) => ApplyFilter();

        private void FilterValueBox_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key != Key.Enter)
                return;

            AddRule_Click(sender, new RoutedEventArgs());
            e.Handled = true;
        }

        private void AddRule_Click(object sender, RoutedEventArgs e)
        {
            if (!_isReady || FilterColumnBox == null || FilterRelationBox == null || FilterActionBox == null || FilterValueBox == null)
                return;

            string column = (FilterColumnBox.SelectedItem as ComboBoxItem)?.Content?.ToString() ?? "Process Name";
            string relation = (FilterRelationBox.SelectedItem as ComboBoxItem)?.Content?.ToString() ?? "is";
            string action = (FilterActionBox.SelectedItem as ComboBoxItem)?.Content?.ToString() ?? "Include";
            string value = FilterValueBox.Text?.Trim() ?? "";

            if (string.IsNullOrWhiteSpace(value))
                return;

            _rules.Add(new ProcessFilterRule
            {
                Enabled = true,
                Column = column,
                Relation = relation,
                Value = value,
                Action = action
            });

            FilterValueBox.Text = "";
            ApplyFilter();
        }

        private void RemoveRule_Click(object sender, RoutedEventArgs e)
        {
            if (RulesGrid.SelectedItem is not ProcessFilterRule rule)
                return;

            _rules.Remove(rule);
            ApplyFilter();
        }

        private void RulesGrid_CurrentCellChanged(object? sender, EventArgs e) => ApplyFilter();
        private void RuleEnabled_Click(object sender, RoutedEventArgs e) => ApplyFilter();

        private void MoveRuleUp_Click(object sender, RoutedEventArgs e)
        {
            MoveRule(-1);
        }

        private void MoveRuleDown_Click(object sender, RoutedEventArgs e)
        {
            MoveRule(1);
        }

        private void ResetRules_Click(object sender, RoutedEventArgs e)
        {
            _rules.Clear();
            if (QuickSearchBox != null)
                QuickSearchBox.Text = "";
            if (FilterValueBox != null)
                FilterValueBox.Text = "";
            ApplyFilter();
        }

        private void RefreshList()
        {
            int selectedPid = (ProcessGrid.SelectedItem as ProcessItem)?.Pid ?? 0;
            var parentByPid = BuildParentPidMap();
            var now = DateTime.UtcNow;
            var list = new List<ProcessItem>();
            var presentPids = new HashSet<int>();
            string windowsDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);

            foreach (var p in Process.GetProcesses())
            {
                try
                {
                    presentPids.Add(p.Id);

                    string path = "";
                    string fileName = "";
                    string appName = "";
                    string company = "";
                    string architecture = "-";
                    double cpuPct = 0;
                    string integrity = "Unknown";
                    bool isAppContainer = false;

                    try
                    {
                        var cpuNow = p.TotalProcessorTime;
                        if (_cpuBaseline.TryGetValue(p.Id, out var prev))
                        {
                            var sec = Math.Max(0.25, (now - prev.ts).TotalSeconds);
                            cpuPct = (cpuNow - prev.cpu).TotalSeconds / sec / Math.Max(1, Environment.ProcessorCount) * 100.0;
                            if (cpuPct < 0) cpuPct = 0;
                        }
                        _cpuBaseline[p.Id] = (cpuNow, now);
                    }
                    catch
                    {
                    }

                    try
                    {
                        path = p.MainModule?.FileName ?? "";
                    }
                    catch
                    {
                    }

                    architecture = TryGetArchitecture(p);

                    if (!string.IsNullOrWhiteSpace(path))
                    {
                        var meta = GetPathMetadata(path, p.ProcessName);
                        fileName = meta.FileName;
                        appName = meta.AppName;
                        company = meta.Company;
                    }

                    if (string.IsNullOrWhiteSpace(appName))
                        appName = p.ProcessName;

                    int parentPid = parentByPid.TryGetValue(p.Id, out var pp) ? pp : 0;
                    bool isChild = parentPid > 0;

                    bool isSystemOrWindows =
                        p.SessionId == 0 ||
                        p.ProcessName.Equals("System", StringComparison.OrdinalIgnoreCase) ||
                        (!string.IsNullOrWhiteSpace(path) && path.StartsWith(windowsDir, StringComparison.OrdinalIgnoreCase));

                    bool isSigned = string.IsNullOrWhiteSpace(path) ? false : GetPathMetadata(path, p.ProcessName).IsSigned;
                    bool isUnsigned = !isSigned && !string.IsNullOrWhiteSpace(path);

                    if (TryGetIntegrityInfo(p, out var integrityLevel, out var appContainer))
                    {
                        integrity = integrityLevel;
                        isAppContainer = appContainer;
                    }

                    var row = new ProcessItem
                    {
                        Name = p.ProcessName,
                        AppName = appName,
                        Company = company,
                        FileName = fileName,
                        Architecture = architecture,
                        Pid = p.Id,
                        ParentPid = parentPid,
                        CpuPercentValue = cpuPct,
                        CpuPercent = cpuPct.ToString("0.0", CultureInfo.InvariantCulture),
                        IntegrityLevel = integrity,
                        IsAppContainer = isAppContainer,
                        SandboxStatus = isAppContainer ? "AppContainer" : "-",
                        IsSigned = isSigned,
                        IsUnsigned = isUnsigned,
                        SignedStatus = isSigned ? "Yes" : "No",
                        IsSystemOrWindows = isSystemOrWindows,
                        Relation = isChild ? "Child" : "Head",
                        Path = path
                    };

                    ApplyRowTheme(row);
                    list.Add(row);
                }
                finally
                {
                    p.Dispose();
                }
            }

            foreach (var stale in _cpuBaseline.Keys.Where(k => !presentPids.Contains(k)).ToList())
                _cpuBaseline.Remove(stale);

            var byPid = list.ToDictionary(x => x.Pid, x => x.Name);
            foreach (var item in list)
            {
                if (item.ParentPid > 0 && byPid.TryGetValue(item.ParentPid, out var parentName))
                    item.ParentName = $"{parentName} ({item.ParentPid})";
                else
                    item.ParentName = item.ParentPid > 0 ? item.ParentPid.ToString(CultureInfo.InvariantCulture) : "-";
            }

            _all.Clear();
            _all.AddRange(list
                .OrderBy(x => x.IsUnsigned ? 0 : 1)
                .ThenBy(x => x.IsAppContainer ? 0 : 1)
                .ThenBy(x => x.IsSystemOrWindows ? 1 : 0)
                .ThenByDescending(x => x.CpuPercentValue)
                .ThenBy(x => x.Name, StringComparer.OrdinalIgnoreCase));

            ApplyFilter();

            if (selectedPid > 0)
            {
                var selected = _view.FirstOrDefault(x => x.Pid == selectedPid);
                if (selected != null)
                    ProcessGrid.SelectedItem = selected;
            }
        }

        private void RefreshIntervalBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (!_isReady || RefreshIntervalBox.SelectedItem is not ComboBoxItem item)
                return;

            string label = item.Content?.ToString() ?? "2s";
            int sec = label.StartsWith("1", StringComparison.Ordinal) ? 1 :
                      label.StartsWith("5", StringComparison.Ordinal) ? 5 : 2;

            _refreshTimer.Interval = TimeSpan.FromSeconds(sec);
        }

        private void ApplyFilter()
        {
            if (!_isReady || ProcessGrid == null || ResultCountBlock == null)
                return;

            string q = QuickSearchBox?.Text?.Trim() ?? "";

            IEnumerable<ProcessItem> filtered = _all;

            if (!string.IsNullOrWhiteSpace(q))
            {
                filtered = filtered.Where(x =>
                    x.Name.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                    x.AppName.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                    x.Company.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                    x.FileName.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                    x.Architecture.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                    x.Pid.ToString(CultureInfo.InvariantCulture).Contains(q, StringComparison.OrdinalIgnoreCase) ||
                    x.Path.Contains(q, StringComparison.OrdinalIgnoreCase));
            }

            if (_rules.Count > 0)
                filtered = filtered.Where(PassesRules);

            _view.Clear();
            foreach (var item in filtered)
                _view.Add(item);

            ResultCountBlock.Text = $"{_view.Count} process(es)";
        }

        private bool PassesRules(ProcessItem item)
        {
            var active = _rules.Where(r => r.Enabled).ToList();
            if (active.Count == 0)
                return true;

            bool hasIncludeRules = active.Any(r => r.Action.Equals("Include", StringComparison.OrdinalIgnoreCase));
            bool include = !hasIncludeRules;

            foreach (var rule in active)
            {
                if (!RuleMatches(item, rule))
                    continue;

                include = rule.Action.Equals("Include", StringComparison.OrdinalIgnoreCase);
            }

            return include;
        }

        private void MoveRule(int delta)
        {
            if (RulesGrid.SelectedItem is not ProcessFilterRule rule)
                return;

            int oldIndex = _rules.IndexOf(rule);
            if (oldIndex < 0)
                return;

            int newIndex = oldIndex + delta;
            if (newIndex < 0 || newIndex >= _rules.Count)
                return;

            _rules.Move(oldIndex, newIndex);
            RulesGrid.SelectedItem = rule;
            RulesGrid.ScrollIntoView(rule);
            ApplyFilter();
        }

        private static bool RuleMatches(ProcessItem item, ProcessFilterRule rule)
        {
            string left = GetRuleField(item, rule.Column);
            string right = rule.Value ?? "";
            string relation = rule.Relation?.Trim().ToLowerInvariant() ?? "is";

            return relation switch
            {
                "is" => string.Equals(left, right, StringComparison.OrdinalIgnoreCase),
                "contains" => left.Contains(right, StringComparison.OrdinalIgnoreCase),
                "begins with" => left.StartsWith(right, StringComparison.OrdinalIgnoreCase),
                "ends with" => left.EndsWith(right, StringComparison.OrdinalIgnoreCase),
                "greater than" => TryCompareNumeric(left, right, out var gt) && gt > 0,
                "less than" => TryCompareNumeric(left, right, out var lt) && lt < 0,
                _ => string.Equals(left, right, StringComparison.OrdinalIgnoreCase)
            };
        }

        private static string GetRuleField(ProcessItem item, string column)
        {
            return column switch
            {
                "Architecture" => item.Architecture,
                "Process Name" => item.Name,
                "App Name" => item.AppName,
                "Company" => item.Company,
                "File Name" => item.FileName,
                "PID" => item.Pid.ToString(CultureInfo.InvariantCulture),
                "CPU %" => item.CpuPercent,
                "Integrity" => item.IntegrityLevel,
                "Signed" => item.SignedStatus,
                "Sandbox" => item.SandboxStatus,
                "Relation" => item.Relation,
                "Parent" => item.ParentName,
                "Path" => item.Path,
                _ => item.Name
            };
        }

        private static bool TryCompareNumeric(string left, string right, out int compareResult)
        {
            compareResult = 0;
            if (!double.TryParse(left, NumberStyles.Float, CultureInfo.InvariantCulture, out var a))
                return false;
            if (!double.TryParse(right, NumberStyles.Float, CultureInfo.InvariantCulture, out var b))
                return false;

            compareResult = a.CompareTo(b);
            return true;
        }

        private static void ApplyRowTheme(ProcessItem item)
        {
            if (item.IsUnsigned)
            {
                item.RowBackground = Brush(0x33, 0x50, 0x1F, 0x1F);
                item.RowBorderBrush = Brush(0xAA, 0xE3, 0x6B, 0x6B);
                item.RowForeground = Brush(0xFF, 0xF4, 0xD7, 0xD7);
                return;
            }

            if (item.IsAppContainer)
            {
                item.RowBackground = Brush(0x33, 0x3A, 0x2A, 0x58);
                item.RowBorderBrush = Brush(0x99, 0xB0, 0x7A, 0xE8);
                item.RowForeground = Brushes.WhiteSmoke;
                return;
            }

            if (item.IntegrityLevel.Equals("Low", StringComparison.OrdinalIgnoreCase))
            {
                item.RowBackground = Brush(0x2D, 0x4C, 0x41, 0x1D);
                item.RowBorderBrush = Brush(0x88, 0xD1, 0xB0, 0x5C);
                return;
            }

            if (item.IntegrityLevel.Equals("High", StringComparison.OrdinalIgnoreCase) ||
                item.IntegrityLevel.Equals("System", StringComparison.OrdinalIgnoreCase))
            {
                item.RowBackground = Brush(0x24, 0x2D, 0x3C, 0x52);
                item.RowBorderBrush = Brush(0x70, 0x8A, 0xA8, 0xC7);
                return;
            }

            if (item.IsSystemOrWindows)
            {
                item.RowBackground = Brush(0x22, 0x23, 0x23, 0x23);
                item.RowBorderBrush = Brush(0x55, 0x5A, 0x5A, 0x5A);
                item.RowForeground = Brush(0xFF, 0xB8, 0xB8, 0xB8);
                return;
            }

            item.RowBackground = Brushes.Transparent;
            item.RowBorderBrush = Brushes.Transparent;
            item.RowForeground = Brushes.WhiteSmoke;
        }

        private static SolidColorBrush Brush(byte a, byte r, byte g, byte b)
        {
            var bsh = new SolidColorBrush(Color.FromArgb(a, r, g, b));
            bsh.Freeze();
            return bsh;
        }

        private bool IsSigned(string path)
        {
            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
                return false;

            if (_signatureCache.TryGetValue(path, out var signed))
                return signed;

            try
            {
#pragma warning disable SYSLIB0057
                _ = X509Certificate.CreateFromSignedFile(path);
#pragma warning restore SYSLIB0057
                _signatureCache[path] = true;
                return true;
            }
            catch
            {
                _signatureCache[path] = false;
                return false;
            }
        }

        private ProcessPathMetadata GetPathMetadata(string path, string fallbackProcessName)
        {
            if (_pathMetadataCache.TryGetValue(path, out var cached))
                return cached;

            var result = new ProcessPathMetadata
            {
                FileName = System.IO.Path.GetFileName(path),
                AppName = fallbackProcessName,
                Company = "",
                IsSigned = IsSigned(path)
            };

            try
            {
                var ver = FileVersionInfo.GetVersionInfo(path);
                if (!string.IsNullOrWhiteSpace(ver.ProductName))
                    result.AppName = ver.ProductName;
                result.Company = ver.CompanyName ?? "";
            }
            catch
            {
            }

            _pathMetadataCache[path] = result;
            return result;
        }

        private static string TryGetArchitecture(Process process)
        {
            try
            {
                if (!Environment.Is64BitOperatingSystem)
                    return "x86";

                if (IsWow64Process2(process.Handle, out ushort processMachine, out ushort nativeMachine))
                {
                    if (processMachine == IMAGE_FILE_MACHINE_UNKNOWN)
                        return MachineToArch(nativeMachine);
                    return MachineToArch(processMachine);
                }
            }
            catch
            {
            }

            try
            {
                if (IsWow64Process(process.Handle, out bool isWow64))
                    return isWow64 ? "x86" : "x64";
            }
            catch
            {
            }

            return "-";
        }

        private static string MachineToArch(ushort machine)
        {
            return machine switch
            {
                IMAGE_FILE_MACHINE_I386 => "x86",
                IMAGE_FILE_MACHINE_AMD64 => "x64",
                IMAGE_FILE_MACHINE_ARM64 => "arm64",
                IMAGE_FILE_MACHINE_ARM => "arm",
                _ => "-"
            };
        }

        private static Dictionary<int, int> BuildParentPidMap()
        {
            var map = new Dictionary<int, int>();
            IntPtr snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (snap == INVALID_HANDLE_VALUE)
                return map;

            try
            {
                var pe = new PROCESSENTRY32();
                pe.dwSize = (uint)Marshal.SizeOf<PROCESSENTRY32>();

                if (!Process32First(snap, ref pe))
                    return map;

                do
                {
                    map[(int)pe.th32ProcessID] = (int)pe.th32ParentProcessID;
                }
                while (Process32Next(snap, ref pe));
            }
            finally
            {
                CloseHandle(snap);
            }

            return map;
        }

        private static bool TryGetIntegrityInfo(Process p, out string integrity, out bool isAppContainer)
        {
            integrity = "Unknown";
            isAppContainer = false;

            IntPtr token = IntPtr.Zero;
            try
            {
                if (!OpenProcessToken(p.Handle, TOKEN_QUERY, out token))
                    return false;

                if (!TryGetIntegrityLevel(token, out integrity))
                    integrity = "Unknown";

                _ = TryGetTokenIsAppContainer(token, out isAppContainer);
                return true;
            }
            catch
            {
                return false;
            }
            finally
            {
                if (token != IntPtr.Zero)
                    CloseHandle(token);
            }
        }

        private static bool TryGetIntegrityLevel(IntPtr token, out string integrity)
        {
            integrity = "Unknown";

            if (!GetTokenInformation(token, TOKEN_INFORMATION_CLASS.TokenIntegrityLevel, IntPtr.Zero, 0, out int cb))
            {
                if (Marshal.GetLastWin32Error() != ERROR_INSUFFICIENT_BUFFER)
                    return false;
            }

            IntPtr pTIL = Marshal.AllocHGlobal(cb);
            try
            {
                if (!GetTokenInformation(token, TOKEN_INFORMATION_CLASS.TokenIntegrityLevel, pTIL, cb, out _))
                    return false;

                var til = Marshal.PtrToStructure<TOKEN_MANDATORY_LABEL>(pTIL);
                IntPtr pSid = til.Label.Sid;
                int subAuthCount = Marshal.ReadByte(GetSidSubAuthorityCount(pSid));
                int rid = Marshal.ReadInt32(GetSidSubAuthority(pSid, subAuthCount - 1));

                integrity = rid switch
                {
                    >= SECURITY_MANDATORY_PROTECTED_PROCESS_RID => "Protected",
                    >= SECURITY_MANDATORY_SYSTEM_RID => "System",
                    >= SECURITY_MANDATORY_HIGH_RID => "High",
                    >= SECURITY_MANDATORY_MEDIUM_RID => "Medium",
                    >= SECURITY_MANDATORY_LOW_RID => "Low",
                    _ => "Untrusted"
                };
                return true;
            }
            finally
            {
                Marshal.FreeHGlobal(pTIL);
            }
        }

        private static bool TryGetTokenIsAppContainer(IntPtr token, out bool isAppContainer)
        {
            isAppContainer = false;
            int size = sizeof(int);
            IntPtr p = Marshal.AllocHGlobal(size);
            try
            {
                if (!GetTokenInformation(token, TOKEN_INFORMATION_CLASS.TokenIsAppContainer, p, size, out _))
                    return false;
                isAppContainer = Marshal.ReadInt32(p) != 0;
                return true;
            }
            finally
            {
                Marshal.FreeHGlobal(p);
            }
        }

        private void Select_Click(object sender, RoutedEventArgs e)
        {
            if (ProcessGrid.SelectedItem is not ProcessItem item)
                return;

            SelectedPid = item.Pid;
            DialogResult = true;
            Close();
        }

        private void ProcessGrid_MouseDoubleClick(object sender, MouseButtonEventArgs e)
        {
            Select_Click(sender, e);
        }

        private void OpenExe_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new OpenFileDialog
            {
                Filter = "Executable (*.exe)|*.exe",
                CheckFileExists = true,
                Multiselect = false
            };

            if (dlg.ShowDialog(this) != true)
                return;

            try
            {
                var started = Process.Start(new ProcessStartInfo(dlg.FileName)
                {
                    UseShellExecute = true
                });

                if (started == null)
                    return;

                SelectedPid = started.Id;
                DialogResult = true;
                Close();
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.Message, "Launch failed", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void Cancel_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = false;
            Close();
        }

        private static readonly IntPtr INVALID_HANDLE_VALUE = new(-1);

        private const uint TH32CS_SNAPPROCESS = 0x00000002;
        private const uint TOKEN_QUERY = 0x0008;
        private const int ERROR_INSUFFICIENT_BUFFER = 122;
        private const ushort IMAGE_FILE_MACHINE_UNKNOWN = 0x0000;
        private const ushort IMAGE_FILE_MACHINE_I386 = 0x014c;
        private const ushort IMAGE_FILE_MACHINE_AMD64 = 0x8664;
        private const ushort IMAGE_FILE_MACHINE_ARM = 0x01c0;
        private const ushort IMAGE_FILE_MACHINE_ARM64 = 0xAA64;

        private const int SECURITY_MANDATORY_LOW_RID = 0x1000;
        private const int SECURITY_MANDATORY_MEDIUM_RID = 0x2000;
        private const int SECURITY_MANDATORY_HIGH_RID = 0x3000;
        private const int SECURITY_MANDATORY_SYSTEM_RID = 0x4000;
        private const int SECURITY_MANDATORY_PROTECTED_PROCESS_RID = 0x5000;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct PROCESSENTRY32
        {
            public uint dwSize;
            public uint cntUsage;
            public uint th32ProcessID;
            public IntPtr th32DefaultHeapID;
            public uint th32ModuleID;
            public uint cntThreads;
            public uint th32ParentProcessID;
            public int pcPriClassBase;
            public uint dwFlags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string szExeFile;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SID_AND_ATTRIBUTES
        {
            public IntPtr Sid;
            public int Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct TOKEN_MANDATORY_LABEL
        {
            public SID_AND_ATTRIBUTES Label;
        }

        private enum TOKEN_INFORMATION_CLASS
        {
            TokenUser = 1,
            TokenGroups,
            TokenPrivileges,
            TokenOwner,
            TokenPrimaryGroup,
            TokenDefaultDacl,
            TokenSource,
            TokenType,
            TokenImpersonationLevel,
            TokenStatistics,
            TokenRestrictedSids,
            TokenSessionId,
            TokenGroupsAndPrivileges,
            TokenSessionReference,
            TokenSandBoxInert,
            TokenAuditPolicy,
            TokenOrigin,
            TokenElevationType,
            TokenLinkedToken,
            TokenElevation,
            TokenHasRestrictions,
            TokenAccessInformation,
            TokenVirtualizationAllowed,
            TokenVirtualizationEnabled,
            TokenIntegrityLevel,
            TokenUIAccess,
            TokenMandatoryPolicy,
            TokenLogonSid,
            TokenIsAppContainer = 29
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool Process32First(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool Process32Next(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool GetTokenInformation(
            IntPtr TokenHandle,
            TOKEN_INFORMATION_CLASS TokenInformationClass,
            IntPtr TokenInformation,
            int TokenInformationLength,
            out int ReturnLength);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern IntPtr GetSidSubAuthority(IntPtr pSid, int nSubAuthority);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern IntPtr GetSidSubAuthorityCount(IntPtr pSid);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool IsWow64Process(IntPtr hProcess, out bool wow64Process);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool IsWow64Process2(IntPtr hProcess, out ushort processMachine, out ushort nativeMachine);
    }

    public sealed class ProcessFilterRule
    {
        public bool Enabled { get; set; } = true;
        public string Column { get; set; } = "";
        public string Relation { get; set; } = "is";
        public string Value { get; set; } = "";
        public string Action { get; set; } = "Include";
    }

    internal sealed class ProcessPathMetadata
    {
        public string FileName { get; init; } = "";
        public string AppName { get; set; } = "";
        public string Company { get; set; } = "";
        public bool IsSigned { get; init; }
    }

    public sealed class ProcessItem
    {
        public string Name { get; init; } = "";
        public string AppName { get; init; } = "";
        public string Company { get; init; } = "";
        public string FileName { get; init; } = "";
        public string Architecture { get; init; } = "-";
        public int Pid { get; init; }
        public int ParentPid { get; init; }
        public string ParentName { get; set; } = "-";
        public string CpuPercent { get; init; } = "0.0";
        public double CpuPercentValue { get; init; }
        public string IntegrityLevel { get; init; } = "Unknown";
        public bool IsAppContainer { get; init; }
        public string SandboxStatus { get; init; } = "-";
        public bool IsSigned { get; init; }
        public bool IsUnsigned { get; init; }
        public string SignedStatus { get; init; } = "No";
        public bool IsSystemOrWindows { get; init; }
        public string Relation { get; init; } = "Head";
        public string Path { get; init; } = "";

        public Brush RowBackground { get; set; } = Brushes.Transparent;
        public Brush RowBorderBrush { get; set; } = Brushes.Transparent;
        public Brush RowForeground { get; set; } = Brushes.WhiteSmoke;
    }
}
