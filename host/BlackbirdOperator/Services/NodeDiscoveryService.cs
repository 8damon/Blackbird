using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using BlackbirdOperator.Models;

namespace BlackbirdOperator.Services;

public sealed class NodeDiscoveryService : IDisposable
{
    public const int DiscoveryPort = 49371;
    public const int DefaultStatusPort = 49372;

    private const string DiscoveryQuery = "BLACKBIRD_DISCOVER_V1";
    private const string StatusQuery = "BLACKBIRD_STATUS_V1\n";
    private const int ManualQueryTimeoutMs = 3000;
    private const int ActiveProbeTimeoutMs = 600;
    private const int ActiveProbeConcurrency = 96;
    private const int ProgressReportStride = 8;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true
    };

    private readonly CancellationTokenSource _cts = new();
    private readonly OperatorDiscoveryOptions _options;
    private readonly List<AdapterBinding> _adapterBindings;
    private readonly List<UdpClient> _listeners = [];
    private readonly List<Task> _receiveTasks = [];

    private sealed class AdapterBinding
    {
        public required string InterfaceId { get; init; }
        public required string Name { get; init; }
        public required IPAddress Address { get; init; }
        public required IPAddress Mask { get; init; }
        public required IPAddress Broadcast { get; init; }
        public required int PrefixLength { get; init; }
    }

    public event Action<OperatorNode>? NodeDiscovered;

    private string SelectedBindingSummary => _adapterBindings.Count == 0
        ? "selected private adapters"
        : string.Join(", ", _adapterBindings.Select(binding => $"{binding.Name} {binding.Address}/{binding.PrefixLength}"));

    public NodeDiscoveryService(OperatorDiscoveryOptions options)
    {
        _options = options;
        _adapterBindings = GetEligibleBindings(options).ToList();
    }

    public static IReadOnlyList<OperatorAdapterOption> GetAdapterOptions()
    {
        return GetEligibleBindings(new OperatorDiscoveryOptions()).Select(binding => new OperatorAdapterOption
        {
            InterfaceId = binding.InterfaceId,
            Name = binding.Name,
            Address = binding.Address.ToString(),
            Prefix = binding.PrefixLength.ToString()
        }).ToList();
    }

    public void Start()
    {
        if (!_options.EnablePassiveDiscovery || _listeners.Count != 0)
        {
            return;
        }

        foreach (AdapterBinding binding in _adapterBindings)
        {
            UdpClient listener = CreateDiscoverySocket(binding.Address);
            _listeners.Add(listener);
            _receiveTasks.Add(Task.Run(() => ReceiveLoopAsync(listener, _cts.Token)));
        }
    }

    public async Task SendDiscoveryProbeAsync(
        IProgress<(double Percent, string Status, string Detail)>? progress = null,
        CancellationToken cancellationToken = default)
    {
        progress?.Report((8, "Preparing discovery...", $"Validating {SelectedBindingSummary}."));

        if (_options.EnablePassiveDiscovery)
        {
            byte[] payload = Encoding.ASCII.GetBytes(DiscoveryQuery);
            using var sender = new UdpClient(AddressFamily.InterNetwork) { EnableBroadcast = true };
            IPAddress[] targets = GetBroadcastTargets().ToArray();
            for (int index = 0; index < targets.Length; index++)
            {
                IPAddress target = targets[index];
                await sender.SendAsync(payload, new IPEndPoint(target, DiscoveryPort), cancellationToken);
                double percent = 18 + ((index + 1) / (double)Math.Max(1, targets.Length)) * 16;
                progress?.Report((percent, "Broadcasting discovery...", $"Sent probe to {target} via {SelectedBindingSummary}."));
            }
        }
        else
        {
            progress?.Report((28, "Passive discovery disabled.", $"Skipping UDP broadcast and using the configured active policy on {SelectedBindingSummary}."));
        }

        if (_options.EnableActiveSubnetProbe)
        {
            await ProbeSelectedSubnetsAsync(progress, cancellationToken);
        }
        else
        {
            progress?.Report((84, "Awaiting replies...", $"Passive discovery sent on {SelectedBindingSummary}. Waiting briefly for node responses."));
            await Task.Delay(300, cancellationToken);
        }

        progress?.Report((100, "Discovery complete.", $"Node refresh finished on {SelectedBindingSummary}."));
    }

    public async Task<OperatorNode?> QueryStatusAsync(string address, int statusPort, CancellationToken cancellationToken = default)
    {
        IPAddress selectedAddress;
        if (IPAddress.TryParse(address, out IPAddress? parsedAddress) && parsedAddress.AddressFamily == AddressFamily.InterNetwork)
        {
            selectedAddress = parsedAddress;
        }
        else
        {
            IPAddress[] addresses = await Dns.GetHostAddressesAsync(address, cancellationToken);
            selectedAddress = addresses.FirstOrDefault(ip => ip.AddressFamily == AddressFamily.InterNetwork)
                ?? throw new InvalidOperationException($"No IPv4 address resolved for '{address}'.");
        }

        return await QueryStatusAtAddressAsync(selectedAddress, statusPort > 0 ? statusPort : DefaultStatusPort, ManualQueryTimeoutMs, cancellationToken);
    }

    private async Task<OperatorNode?> QueryStatusAtAddressAsync(IPAddress address, int statusPort, int timeoutMs, CancellationToken cancellationToken)
    {
        using var client = new TcpClient(AddressFamily.InterNetwork)
        {
            NoDelay = true
        };
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(TimeSpan.FromMilliseconds(timeoutMs));
        await client.ConnectAsync(address, statusPort, timeoutCts.Token);
        using NetworkStream stream = client.GetStream();
        byte[] request = Encoding.ASCII.GetBytes(StatusQuery);
        await stream.WriteAsync(request, timeoutCts.Token);
        await stream.FlushAsync(timeoutCts.Token);

        using var buffer = new MemoryStream();
        byte[] chunk = new byte[2048];
        while (true)
        {
            int read = await stream.ReadAsync(chunk, 0, chunk.Length, timeoutCts.Token);
            if (read <= 0)
            {
                break;
            }

            buffer.Write(chunk, 0, read);
            if (read < chunk.Length)
            {
                break;
            }
        }

        string payload = Encoding.UTF8.GetString(buffer.ToArray()).Trim();
        if (string.IsNullOrWhiteSpace(payload))
        {
            return null;
        }

        BlackbirdNodeWireMessage? message = JsonSerializer.Deserialize<BlackbirdNodeWireMessage>(payload, JsonOptions);
        return message is null ? null : MapNode(message, address.ToString());
    }

    private async Task ReceiveLoopAsync(UdpClient listener, CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            UdpReceiveResult result;

            try
            {
                result = await listener.ReceiveAsync(cancellationToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch
            {
                await Task.Delay(250, cancellationToken);
                continue;
            }

            string payload = Encoding.UTF8.GetString(result.Buffer);
            if (string.IsNullOrWhiteSpace(payload))
            {
                continue;
            }

            BlackbirdNodeWireMessage? message;
            try
            {
                message = JsonSerializer.Deserialize<BlackbirdNodeWireMessage>(payload, JsonOptions);
            }
            catch
            {
                continue;
            }

            if (message is null || !string.Equals(message.Kind, "blackbird.node.beacon", StringComparison.Ordinal))
            {
                continue;
            }

            NodeDiscovered?.Invoke(MapNode(message, result.RemoteEndPoint.Address.ToString()));
        }
    }

    private async Task ProbeSelectedSubnetsAsync(
        IProgress<(double Percent, string Status, string Detail)>? progress,
        CancellationToken cancellationToken)
    {
        var candidates = new List<IPAddress>();
        foreach (AdapterBinding binding in _adapterBindings)
        {
            foreach (IPAddress candidate in EnumerateProbeCandidates(binding, _options.MaxProbeHosts))
            {
                candidates.Add(candidate);
            }
        }

        if (candidates.Count == 0)
        {
            progress?.Report((88, "No probe candidates.", $"{SelectedBindingSummary} did not expose a bounded private subnet to scan."));
            return;
        }

        int completed = 0;
        int discovered = 0;
        progress?.Report((36, "Scanning subnet...", $"Fast-probing {candidates.Count} address(es) on {SelectedBindingSummary}."));

        using var semaphore = new SemaphoreSlim(Math.Min(ActiveProbeConcurrency, Math.Max(8, candidates.Count)));
        var tasks = candidates.Select(async candidate =>
        {
            await semaphore.WaitAsync(cancellationToken);
            try
            {
                OperatorNode? node = await QueryStatusAtAddressAsync(candidate, DefaultStatusPort, ActiveProbeTimeoutMs, cancellationToken);
                if (node is not null)
                {
                    Interlocked.Increment(ref discovered);
                    NodeDiscovered?.Invoke(node);
                }
            }
            catch
            {
            }
            finally
            {
                int done = Interlocked.Increment(ref completed);
                if (done == candidates.Count || done == 1 || done % ProgressReportStride == 0)
                {
                    double percent = 36 + (done / (double)Math.Max(1, candidates.Count)) * 60;
                    progress?.Report((percent, "Scanning subnet...", $"[{SelectedBindingSummary}] Checked {done}/{candidates.Count} address(es); found {Volatile.Read(ref discovered)} node(s)."));
                }
                semaphore.Release();
            }
        });

        await Task.WhenAll(tasks);
    }

    private static IEnumerable<AdapterBinding> GetEligibleBindings(OperatorDiscoveryOptions options)
    {
        foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.OperationalStatus != OperationalStatus.Up || nic.NetworkInterfaceType == NetworkInterfaceType.Loopback)
            {
                continue;
            }
            if (!string.IsNullOrWhiteSpace(options.PreferredInterfaceId) &&
                !string.Equals(nic.Id, options.PreferredInterfaceId, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            IPInterfaceProperties properties;
            try
            {
                properties = nic.GetIPProperties();
            }
            catch
            {
                continue;
            }

            foreach (UnicastIPAddressInformation unicast in properties.UnicastAddresses)
            {
                if (unicast.Address.AddressFamily != AddressFamily.InterNetwork || unicast.IPv4Mask is null)
                {
                    continue;
                }
                if (!IsPrivateAddress(unicast.Address))
                {
                    continue;
                }

                byte[] addressBytes = unicast.Address.GetAddressBytes();
                byte[] maskBytes = unicast.IPv4Mask.GetAddressBytes();
                var broadcastBytes = new byte[4];
                int prefixLength = 0;
                for (int i = 0; i < 4; i++)
                {
                    broadcastBytes[i] = (byte)(addressBytes[i] | (~maskBytes[i] & 0xFF));
                    prefixLength += CountBits(maskBytes[i]);
                }

                yield return new AdapterBinding
                {
                    InterfaceId = nic.Id,
                    Name = nic.Name,
                    Address = unicast.Address,
                    Mask = unicast.IPv4Mask,
                    Broadcast = new IPAddress(broadcastBytes),
                    PrefixLength = prefixLength
                };
            }
        }
    }

    private IEnumerable<IPAddress> GetBroadcastTargets()
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            IPAddress.Broadcast.ToString()
        };

        yield return IPAddress.Broadcast;

        foreach (AdapterBinding binding in _adapterBindings)
        {
            if (seen.Add(binding.Broadcast.ToString()))
            {
                yield return binding.Broadcast;
            }
        }
    }

    private static IEnumerable<IPAddress> EnumerateProbeCandidates(AdapterBinding binding, int maxHosts)
    {
        uint address = ToUInt32(binding.Address);
        uint mask = ToUInt32(binding.Mask);
        uint network = address & mask;
        uint broadcast = network | ~mask;
        uint totalHosts = broadcast - network + 1u;
        if (totalHosts > (uint)Math.Max(4, maxHosts))
        {
            yield break;
        }

        for (uint current = network + 1u; current < broadcast; current++)
        {
            if (current == address)
            {
                continue;
            }
            yield return FromUInt32(current);
        }
    }

    private static bool IsPrivateAddress(IPAddress address)
    {
        byte[] bytes = address.GetAddressBytes();
        return bytes[0] == 10 ||
               (bytes[0] == 192 && bytes[1] == 168) ||
               (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) ||
               (bytes[0] == 169 && bytes[1] == 254);
    }

    private static int CountBits(byte value)
    {
        int count = 0;
        while (value != 0)
        {
            count += value & 1;
            value >>= 1;
        }
        return count;
    }

    private static uint ToUInt32(IPAddress address)
    {
        byte[] bytes = address.GetAddressBytes();
        return ((uint)bytes[0] << 24) | ((uint)bytes[1] << 16) | ((uint)bytes[2] << 8) | bytes[3];
    }

    private static IPAddress FromUInt32(uint value)
    {
        return new IPAddress(new[]
        {
            (byte)((value >> 24) & 0xFF),
            (byte)((value >> 16) & 0xFF),
            (byte)((value >> 8) & 0xFF),
            (byte)(value & 0xFF)
        });
    }

    private static UdpClient CreateDiscoverySocket(IPAddress localAddress)
    {
        var client = new UdpClient(AddressFamily.InterNetwork);
        client.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
        client.EnableBroadcast = true;
        client.Client.Bind(new IPEndPoint(localAddress, DiscoveryPort));
        return client;
    }

    private static OperatorNode MapNode(BlackbirdNodeWireMessage message, string address)
    {
        return new OperatorNode
        {
            NodeId = message.NodeId,
            HostName = message.HostName,
            DisplayName = string.IsNullOrWhiteSpace(message.DisplayName) ? message.HostName : message.DisplayName,
            Address = address,
            ControllerVersion = message.ControllerVersion,
            OsVersion = message.OsVersion,
            KernelVersion = message.KernelVersion,
            StatusPort = message.StatusPort > 0 ? message.StatusPort : DefaultStatusPort,
            CommandPort = message.CommandPort,
            IdentityFingerprint = message.IdentityFingerprint ?? string.Empty,
            Busy = message.Busy,
            DriverConnected = message.DriverConnected,
            ThreatIntelEnabled = message.ThreatIntelEnabled,
            ThreatIntelEnableError = message.ThreatIntelEnableError,
            ActiveClients = message.ActiveClients,
            LastSeenUtc = DateTime.UtcNow
        };
    }

    public void Dispose()
    {
        _cts.Cancel();
        foreach (UdpClient listener in _listeners)
        {
            listener.Dispose();
        }
        _listeners.Clear();
        try
        {
            Task.WaitAll(_receiveTasks.ToArray(), 1000);
        }
        catch
        {
        }
        _receiveTasks.Clear();
        _cts.Dispose();
    }
}




