using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;
using Microsoft.Win32;
using BlackbirdOperator.Models;
using BlackbirdOperator.Services;

namespace BlackbirdOperator;

public partial class MainWindow : Window
{
    private const int DwmwaUseImmersiveDarkMode = 20;
    private const int DwmwaUseImmersiveDarkModeLegacy = 19;

    [DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int dwAttribute, ref int pvAttribute, int cbAttribute);

    private NodeDiscoveryService _discoveryService;
    private readonly Dictionary<string, OperatorNode> _nodeIndex = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, SecureNodeCommandClient> _secureSessions = new(StringComparer.OrdinalIgnoreCase);
    private OperatorDiscoveryOptions _discoveryOptions;

    public ObservableCollection<OperatorNode> Nodes { get; } = [];

    public MainWindow(OperatorDiscoveryOptions discoveryOptions)
    {
        _discoveryOptions = discoveryOptions;
        _discoveryService = new NodeDiscoveryService(discoveryOptions);

        InitializeComponent();
        DataContext = this;
        UpdateAdapterSummaryText();

        SourceInitialized += MainWindow_SourceInitialized;
        AttachDiscoveryService();
        Loaded += MainWindow_Loaded;
        Closed += MainWindow_Closed;
    }

    private void MainWindow_SourceInitialized(object? sender, EventArgs e)
    {
        ApplyDarkTitleBar();
    }

    private void ApplyDarkTitleBar()
    {
        IntPtr hwnd = new WindowInteropHelper(this).Handle;
        if (hwnd == IntPtr.Zero)
        {
            return;
        }

        int enabled = 1;
        int size = Marshal.SizeOf<int>();
        int result = DwmSetWindowAttribute(hwnd, DwmwaUseImmersiveDarkMode, ref enabled, size);
        if (result != 0)
        {
            _ = DwmSetWindowAttribute(hwnd, DwmwaUseImmersiveDarkModeLegacy, ref enabled, size);
        }
    }

    private void AttachDiscoveryService()
    {
        _discoveryService.NodeDiscovered += OnNodeDiscovered;
    }

    private void DetachDiscoveryService()
    {
        _discoveryService.NodeDiscovered -= OnNodeDiscovered;
    }

    private async void MainWindow_Loaded(object sender, RoutedEventArgs e)
    {
        _discoveryService.Start();
        await RefreshDiscoveryAsync();
    }

    private void MainWindow_Closed(object? sender, EventArgs e)
    {
        foreach (SecureNodeCommandClient client in _secureSessions.Values)
        {
            _ = client.DisposeAsync();
        }

        _secureSessions.Clear();
        _discoveryService.Dispose();
    }

    private async void ConfigureNetworkButton_Click(object sender, RoutedEventArgs e)
    {
        IReadOnlyList<OperatorAdapterOption> adapters = NodeDiscoveryService.GetAdapterOptions();
        var dialog = new OperatorStartupWindow(adapters, _discoveryOptions) { Owner = this };
        bool? result = dialog.ShowDialog();
        if (result != true || dialog.SelectedOptions is null)
        {
            return;
        }

        _discoveryOptions = dialog.SelectedOptions;
        OperatorConfigStore.Save(_discoveryOptions);
        RebuildDiscoveryService();
        UpdateAdapterSummaryText();
        Nodes.Clear();
        _nodeIndex.Clear();
        NodeCountText.Text = "0 node(s)";
        await RefreshDiscoveryAsync();
    }

    private void ResetConfigButton_Click(object sender, RoutedEventArgs e)
    {
        OperatorConfigStore.Reset();
        Hide();

        IReadOnlyList<OperatorAdapterOption> adapters = NodeDiscoveryService.GetAdapterOptions();
        var dialog = new OperatorStartupWindow(adapters, new OperatorDiscoveryOptions());
        bool? result = dialog.ShowDialog();
        if (result != true || dialog.SelectedOptions is null)
        {
            Close();
            return;
        }

        OperatorConfigStore.Save(dialog.SelectedOptions);
        Application.Current.ShutdownMode = ShutdownMode.OnExplicitShutdown;
        var nextWindow = new MainWindow(dialog.SelectedOptions);
        Application.Current.MainWindow = nextWindow;
        nextWindow.Show();
        Application.Current.ShutdownMode = ShutdownMode.OnMainWindowClose;
        Close();
    }

    private void RebuildDiscoveryService()
    {
        DetachDiscoveryService();
        _discoveryService.Dispose();
        _discoveryService = new NodeDiscoveryService(_discoveryOptions);
        AttachDiscoveryService();
        _discoveryService.Start();
    }

    private async void RefreshNodesButton_Click(object sender, RoutedEventArgs e)
    {
        await RefreshDiscoveryAsync();
    }

    private async void ConnectNodeButton_Click(object sender, RoutedEventArgs e)
    {
        await QuerySelectedNodeAsync();
    }

    private async void ConnectAddressButton_Click(object sender, RoutedEventArgs e)
    {
        await QueryManualAddressAsync();
    }

    private async void NodesGrid_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        await QuerySelectedNodeAsync();
    }

    private async void NodesGrid_MouseDoubleClick(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        await QuerySelectedNodeAsync();
    }

    private async void SendFileButton_Click(object sender, RoutedEventArgs e)
    {
        await SendSelectedFileAsync();
    }

    private async void SendCommandButton_Click(object sender, RoutedEventArgs e)
    {
        string command = CommandInputBox.Text?.Trim() ?? string.Empty;
        if (!string.IsNullOrWhiteSpace(command))
        {
            await SendControlCommandAsync(command);
        }
    }

    private async void QuickCommandButton_Click(object sender, RoutedEventArgs e)
    {
        if (sender is System.Windows.Controls.Button btn && btn.Tag is string command)
        {
            await SendControlCommandAsync(command);
        }
    }

    private void CommandInputBox_KeyDown(object sender, System.Windows.Input.KeyEventArgs e)
    {
        if (e.Key == System.Windows.Input.Key.Enter)
        {
            string command = CommandInputBox.Text?.Trim() ?? string.Empty;
            if (!string.IsNullOrWhiteSpace(command))
            {
                _ = SendControlCommandAsync(command);
            }
        }
    }

    private void ClearCommandOutputButton_Click(object sender, RoutedEventArgs e)
    {
        CommandOutputBox.Clear();
    }

    private void FileDropZone_DragOver(object sender, DragEventArgs e)
    {
        if (e.Data.GetDataPresent(DataFormats.FileDrop))
        {
            e.Effects = DragDropEffects.Copy;
        }
        else
        {
            e.Effects = DragDropEffects.None;
        }
        e.Handled = true;
    }

    private void FileDropZone_DragEnter(object sender, DragEventArgs e)
    {
        if (!e.Data.GetDataPresent(DataFormats.FileDrop))
        {
            return;
        }

        FileDropZone.Background = System.Windows.Media.Brushes.Transparent;
        FileDropZone.BorderBrush = FindResource("WinAccentBrush") as System.Windows.Media.Brush ?? FileDropZone.BorderBrush;
        FileDropZone.BorderThickness = new Thickness(0, 1, 0, 0);

        string[] paths = (string[])e.Data.GetData(DataFormats.FileDrop);
        string name = paths?.Length == 1 ? System.IO.Path.GetFileName(paths[0]) : $"{paths?.Length} files";
        FileDropPrimaryText.Text = $"Drop to send  {name}";
        e.Handled = true;
    }

    private void FileDropZone_DragLeave(object sender, DragEventArgs e)
    {
        ResetFileDropZone();
    }

    private async void FileDropZone_Drop(object sender, DragEventArgs e)
    {
        ResetFileDropZone();
        if (!e.Data.GetDataPresent(DataFormats.FileDrop))
        {
            return;
        }

        string[]? paths = e.Data.GetData(DataFormats.FileDrop) as string[];
        if (paths is null || paths.Length == 0)
        {
            return;
        }

        foreach (string path in paths)
        {
            if (System.IO.File.Exists(path))
            {
                await SendFileFromPathAsync(path);
            }
        }
    }

    private void ResetFileDropZone()
    {
        FileDropZone.Background = FindResource("WinHeaderBrush") as System.Windows.Media.Brush;
        FileDropZone.BorderBrush = FindResource("WinBorderBrush") as System.Windows.Media.Brush;
        FileDropPrimaryText.Text = "Drop file to send to node";
    }

    private async Task RefreshDiscoveryAsync()
    {
        var loading = new OperatorLoadingWindow { Owner = this };
        loading.Show();
        loading.SetProgress(8, "Preparing discovery...", "Applying operator-approved discovery settings.");
        await Task.Yield();

        string adapterSummary = GetSelectedAdapterSummary();
        string mode = _discoveryOptions.EnablePassiveDiscovery && _discoveryOptions.EnableActiveSubnetProbe
            ? $"Broadcasting discovery probe and scanning {adapterSummary}."
            : _discoveryOptions.EnableActiveSubnetProbe
                ? $"Scanning {adapterSummary} for operator nodes."
                : $"Broadcasting discovery probe on {adapterSummary}.";
        OperatorStatusText.Text = mode;
        try
        {
            var progress = new Progress<(double Percent, string Status, string Detail)>(update =>
            {
                loading.SetProgress(update.Percent, update.Status, update.Detail);
            });

            await _discoveryService.SendDiscoveryProbeAsync(progress);
            loading.SetProgress(100, "Discovery complete.", $"Found {Nodes.Count} node(s).");
        }
        catch (Exception ex)
        {
            OperatorStatusText.Text = $"Discovery probe failed: {ex.Message}";
            loading.SetProgress(100, "Discovery failed.", ex.Message);
        }
        finally
        {
            await Task.Delay(180);
            loading.Close();
        }
    }

    private void OnNodeDiscovered(OperatorNode node)
    {
        _ = Dispatcher.InvokeAsync(() =>
        {
            OperatorNode activeNode = UpsertNode(node);
            NodeCountText.Text = $"{Nodes.Count} node(s)";
            if (NodesGrid.SelectedItem is null)
            {
                NodesGrid.SelectedItem = activeNode;
            }
        });
    }

    private async Task QuerySelectedNodeAsync()
    {
        if (NodesGrid.SelectedItem is not OperatorNode node)
        {
            return;
        }

        await QueryNodeAsync(node.Address, node.StatusPort, preferExistingNode: node);
    }

    private async Task QueryManualAddressAsync()
    {
        string address = ManualAddressBox.Text?.Trim() ?? string.Empty;
        if (string.IsNullOrWhiteSpace(address))
        {
            OperatorStatusText.Text = "Enter a VM address or hostname to query manually.";
            return;
        }

        await QueryNodeAsync(address, NodeDiscoveryService.DefaultStatusPort, preferExistingNode: null);
    }

    private async Task QueryNodeAsync(string address, int statusPort, OperatorNode? preferExistingNode)
    {
        OperatorNode? detailNode = preferExistingNode;
        if (detailNode is not null)
        {
            PopulateNodeDetail(detailNode, "Querying live status from node.");
        }
        else
        {
            OperatorStatusText.Text = $"Querying {address} over localnet.";
        }

        try
        {
            OperatorNode? refreshed = await _discoveryService.QueryStatusAsync(address, statusPort);
            if (refreshed is null)
            {
                OperatorStatusText.Text = $"No status payload returned from {address}.";
                return;
            }

            OperatorNode activeNode = UpsertNode(refreshed, preferExistingNode);
            NodesGrid.SelectedItem = activeNode;
            ManualAddressBox.Text = activeNode.Address;
            string secureState = await EnsureSecureSessionAsync(activeNode);
            PopulateNodeDetail(activeNode, $"Connected to {activeNode.DisplayName} over localnet. {secureState}");
            NodeCountText.Text = $"{Nodes.Count} node(s)";
        }
        catch (SocketException ex)
        {
            if (detailNode is not null)
            {
                PopulateNodeDetail(detailNode, $"Status query failed: {ex.SocketErrorCode}");
            }
            else
            {
                OperatorStatusText.Text = $"Status query failed: {ex.SocketErrorCode}";
            }
        }
        catch (Exception ex)
        {
            if (detailNode is not null)
            {
                PopulateNodeDetail(detailNode, $"Status query failed: {ex.Message}");
            }
            else
            {
                OperatorStatusText.Text = $"Status query failed: {ex.Message}";
            }
        }
    }

    private async Task<string> EnsureSecureSessionAsync(OperatorNode node)
    {
        if (string.IsNullOrWhiteSpace(node.IdentityFingerprint) || node.CommandPort <= 0)
        {
            return "Secure command channel not advertised by node.";
        }

        string key = $"{node.NodeId}@{node.Address}";
        if (_secureSessions.TryGetValue(key, out SecureNodeCommandClient? existing))
        {
            try
            {
                await existing.SendPingAsync();
                return $"Secure channel established on tcp/{node.CommandPort}.";
            }
            catch
            {
                await existing.DisposeAsync();
                _secureSessions.Remove(key);
            }
        }

        try
        {
            SecureNodeCommandClient client = await SecureNodeCommandClient.ConnectAsync(node, this);
            _secureSessions[key] = client;
            return $"Secure channel established on tcp/{node.CommandPort}.";
        }
        catch (Exception ex)
        {
            return $"Secure command channel unavailable: {ex.Message}";
        }
    }

    private async Task SendControlCommandAsync(string command)
    {
        if (NodesGrid.SelectedItem is not OperatorNode node)
        {
            AppendCommandOutput($"[ERROR] No node selected.");
            return;
        }

        string secureState = await EnsureSecureSessionAsync(node);
        if (!_secureSessions.TryGetValue($"{node.NodeId}@{node.Address}", out SecureNodeCommandClient? client))
        {
            AppendCommandOutput($"[ERROR] {secureState}");
            return;
        }

        AppendCommandOutput($"[>] {command}");
        try
        {
            string reply = await client.SendRawCommandAsync(command);
            AppendCommandOutput($"[<] {reply}");
            CommandInputBox.Clear();
        }
        catch (Exception ex)
        {
            AppendCommandOutput($"[ERROR] {ex.Message}");
        }
    }

    private void AppendCommandOutput(string line)
    {
        if (!string.IsNullOrWhiteSpace(CommandOutputBox.Text))
        {
            CommandOutputBox.AppendText("\n");
        }
        CommandOutputBox.AppendText(line);
        CommandOutputBox.ScrollToEnd();
    }

    private async Task SendSelectedFileAsync()
    {
        if (NodesGrid.SelectedItem is not OperatorNode node)
        {
            OperatorStatusText.Text = "Select a node before sending a file.";
            return;
        }

        var dialog = new OpenFileDialog
        {
            CheckFileExists = true,
            CheckPathExists = true,
            Multiselect = false,
            Title = "Send File To Blackbird Node"
        };
        if (dialog.ShowDialog(this) != true)
        {
            return;
        }

        await SendFileFromPathAsync(dialog.FileName);
    }

    private async Task SendFileFromPathAsync(string filePath)
    {
        if (NodesGrid.SelectedItem is not OperatorNode node)
        {
            AppendCommandOutput("[ERROR] No node selected — select a node before dropping a file.");
            return;
        }

        string fileName = Path.GetFileName(filePath);

        string secureState = await EnsureSecureSessionAsync(node);
        if (!_secureSessions.TryGetValue($"{node.NodeId}@{node.Address}", out SecureNodeCommandClient? client))
        {
            AppendCommandOutput($"[ERROR] {secureState}");
            return;
        }

        AppendCommandOutput($"[>] UPLOAD {fileName} → {node.DisplayName}");
        FileDropPrimaryText.Text = $"Sending {fileName}…";
        try
        {
            SecureNodeCommandClient.RemoteAnalysisResult result = await client.UploadFileForAnalysisAsync(filePath);
            string savedPath = SaveRemoteAnalysis(node, result);
            AppendCommandOutput($"[<] Analysis complete — artifact saved to {savedPath}");
            PopulateNodeDetail(node, $"Remote analysis of {fileName} complete.");
        }
        catch (Exception ex)
        {
            AppendCommandOutput($"[ERROR] {ex.Message}");
        }
        finally
        {
            ResetFileDropZone();
        }
    }

    private static string SaveRemoteAnalysis(OperatorNode node, SecureNodeCommandClient.RemoteAnalysisResult result)
    {
        string root = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Blackbird",
            "Operator",
            "jobs",
            string.IsNullOrWhiteSpace(node.NodeId) ? "unknown-node" : node.NodeId,
            result.JobId);
        Directory.CreateDirectory(root);

        string analysisPath = Path.Combine(root, "analysis.json");
        File.WriteAllBytes(analysisPath, result.AnalysisJsonBytes);
        return analysisPath;
    }

    private OperatorNode UpsertNode(OperatorNode node, OperatorNode? mergeInto = null)
    {
        string key = $"{node.NodeId}@{node.Address}";
        if (mergeInto is not null)
        {
            MergeNode(mergeInto, node);
            if (!_nodeIndex.ContainsKey(key))
            {
                _nodeIndex[key] = mergeInto;
            }

            int mergeIndex = Nodes.IndexOf(mergeInto);
            if (mergeIndex >= 0)
            {
                Nodes[mergeIndex] = mergeInto;
            }
            else
            {
                Nodes.Add(mergeInto);
            }

            return mergeInto;
        }

        if (_nodeIndex.TryGetValue(key, out OperatorNode? existing))
        {
            MergeNode(existing, node);
            int existingIndex = Nodes.IndexOf(existing);
            if (existingIndex >= 0)
            {
                Nodes[existingIndex] = existing;
            }

            return existing;
        }

        _nodeIndex[key] = node;
        Nodes.Add(node);
        return node;
    }

    private static void MergeNode(OperatorNode target, OperatorNode source)
    {
        target.DisplayName = source.DisplayName;
        target.HostName = source.HostName;
        target.Address = source.Address;
        target.ControllerVersion = source.ControllerVersion;
        target.OsVersion = source.OsVersion;
        target.KernelVersion = source.KernelVersion;
        target.StatusPort = source.StatusPort;
        target.CommandPort = source.CommandPort;
        target.IdentityFingerprint = source.IdentityFingerprint;
        target.Busy = source.Busy;
        target.DriverConnected = source.DriverConnected;
        target.ThreatIntelEnabled = source.ThreatIntelEnabled;
        target.ThreatIntelEnableError = source.ThreatIntelEnableError;
        target.ActiveClients = source.ActiveClients;
        target.LastSeenUtc = source.LastSeenUtc;
    }

    private void UpdateAdapterSummaryText()
    {
        AdapterSummaryText.Text = $"Adapter: {GetSelectedAdapterSummary()}";
    }

    private string GetSelectedAdapterSummary()
    {
        IReadOnlyList<OperatorAdapterOption> adapters = NodeDiscoveryService.GetAdapterOptions();
        if (!string.IsNullOrWhiteSpace(_discoveryOptions.PreferredInterfaceId))
        {
            OperatorAdapterOption? match = adapters.FirstOrDefault(item =>
                string.Equals(item.InterfaceId, _discoveryOptions.PreferredInterfaceId, StringComparison.OrdinalIgnoreCase));
            if (match is not null)
            {
                return match.Summary;
            }
        }

        return adapters.FirstOrDefault()?.Summary ?? "Auto-select private adapters";
    }

    private void PopulateNodeDetail(OperatorNode node, string status)
    {
        DetailTitleText.Text = node.DisplayName;
        DetailSubtitleText.Text = $"{node.HostName} · {node.StatusSummary}";
        DetailAddressText.Text = node.Address;
        DetailPortText.Text = node.StatusPort.ToString();
        DetailOsText.Text = node.OsVersion;
        DetailKernelText.Text = node.KernelVersion;
        DetailControllerText.Text = node.ControllerVersion;
        DetailLastSeenText.Text = node.LastSeenUtc == default ? string.Empty : node.LastSeenUtc.ToLocalTime().ToString("u");
        DetailFlagsText.Text =
            $"Driver {(node.DriverConnected ? "Connected" : "Disconnected")}\n" +
            $"Threat Intel {(node.ThreatIntelEnabled ? "Enabled" : $"Disabled (err {node.ThreatIntelEnableError})")}\n" +
            $"Active Clients {node.ActiveClients}\n" +
            $"State {(node.Busy ? "Busy" : "Idle")}\n" +
            $"Node Id {node.NodeId}\n" +
            $"Command Port {node.CommandPort}\n" +
            $"Identity {node.IdentityShort}";
        OperatorStatusText.Text = status;
    }
}
