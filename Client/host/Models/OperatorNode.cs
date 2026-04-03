namespace BlackbirdOperator.Models;

public sealed class OperatorNode
{
    public string NodeId { get; set; } = string.Empty;
    public string HostName { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string Address { get; set; } = string.Empty;
    public string ControllerVersion { get; set; } = string.Empty;
    public string OsVersion { get; set; } = string.Empty;
    public string KernelVersion { get; set; } = string.Empty;
    public int StatusPort { get; set; }
    public int CommandPort { get; set; }
    public string IdentityFingerprint { get; set; } = string.Empty;
    public bool Busy { get; set; }
    public bool DriverConnected { get; set; }
    public bool ThreatIntelEnabled { get; set; }
    public int ThreatIntelEnableError { get; set; }
    public int ActiveClients { get; set; }
    public DateTime LastSeenUtc { get; set; }
    public string DriverStatus => DriverConnected ? "Driver OK" : "Driver Down";
    public string ThreatIntelStatus => ThreatIntelEnabled ? "TI On" : $"TI Off ({ThreatIntelEnableError})";
    public string ObservedDisplay => LastSeenUtc == default ? string.Empty : LastSeenUtc.ToLocalTime().ToString("HH:mm:ss");
    public string StatusSummary => Busy ? $"Busy · clients {ActiveClients}" : $"Idle · clients {ActiveClients}";
    public string IdentityShort => string.IsNullOrWhiteSpace(IdentityFingerprint)
        ? string.Empty
        : (IdentityFingerprint.Length <= 16 ? IdentityFingerprint : IdentityFingerprint[..16]);
}
