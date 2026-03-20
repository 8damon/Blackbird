namespace BlackbirdOperator.Models;

public sealed class OperatorDiscoveryOptions
{
    public bool EnablePassiveDiscovery { get; init; } = true;
    public bool EnableActiveSubnetProbe { get; init; }
    public string? PreferredInterfaceId { get; init; }
    public int MaxProbeHosts { get; init; } = 256;
}
