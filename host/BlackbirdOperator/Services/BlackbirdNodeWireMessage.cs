using System.Text.Json.Serialization;

namespace BlackbirdOperator.Services;

internal sealed class BlackbirdNodeWireMessage
{
    [JsonPropertyName("kind")]
    public string Kind { get; set; } = string.Empty;

    [JsonPropertyName("protocol")]
    public int Protocol { get; set; }

    [JsonPropertyName("nodeId")]
    public string NodeId { get; set; } = string.Empty;

    [JsonPropertyName("hostName")]
    public string HostName { get; set; } = string.Empty;

    [JsonPropertyName("displayName")]
    public string DisplayName { get; set; } = string.Empty;

    [JsonPropertyName("controllerVersion")]
    public string ControllerVersion { get; set; } = string.Empty;

    [JsonPropertyName("osVersion")]
    public string OsVersion { get; set; } = string.Empty;

    [JsonPropertyName("kernelVersion")]
    public string KernelVersion { get; set; } = string.Empty;

    [JsonPropertyName("statusPort")]
    public int StatusPort { get; set; }

    [JsonPropertyName("commandPort")]
    public int CommandPort { get; set; }

    [JsonPropertyName("identityFingerprint")]
    public string IdentityFingerprint { get; set; } = string.Empty;

    [JsonPropertyName("busy")]
    public bool Busy { get; set; }

    [JsonPropertyName("driverConnected")]
    public bool DriverConnected { get; set; }

    [JsonPropertyName("threatIntelEnabled")]
    public bool ThreatIntelEnabled { get; set; }

    [JsonPropertyName("threatIntelEnableError")]
    public int ThreatIntelEnableError { get; set; }

    [JsonPropertyName("activeClients")]
    public int ActiveClients { get; set; }

    [JsonPropertyName("timestampUtc")]
    public string TimestampUtc { get; set; } = string.Empty;
}
