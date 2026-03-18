using System.IO;
using System.Text.Json;

namespace BlackbirdOperator.Services;

internal static class OperatorTrustStore
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true
    };

    internal sealed class NodeTrustEntry
    {
        public string NodeId { get; set; } = string.Empty;
        public string Fingerprint { get; set; } = string.Empty;
        public string Address { get; set; } = string.Empty;
        public DateTime FirstTrustedUtc { get; set; }
        public DateTime LastValidatedUtc { get; set; }
    }

    private sealed class TrustDocument
    {
        public List<NodeTrustEntry> Nodes { get; set; } = [];
    }

    public static string TrustDirectory => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Blackbird",
        "Operator",
        "trust");

    public static string TrustPath => Path.Combine(TrustDirectory, "nodes.json");

    public static NodeTrustEntry? Find(string nodeId)
    {
        if (string.IsNullOrWhiteSpace(nodeId))
        {
            return null;
        }

        TrustDocument document = LoadDocument();
        return document.Nodes.FirstOrDefault(node => string.Equals(node.NodeId, nodeId, StringComparison.OrdinalIgnoreCase));
    }

    public static void SaveOrUpdate(string nodeId, string fingerprint, string address)
    {
        TrustDocument document = LoadDocument();
        NodeTrustEntry? existing = document.Nodes.FirstOrDefault(node => string.Equals(node.NodeId, nodeId, StringComparison.OrdinalIgnoreCase));
        DateTime now = DateTime.UtcNow;
        if (existing is null)
        {
            document.Nodes.Add(new NodeTrustEntry
            {
                NodeId = nodeId,
                Fingerprint = fingerprint,
                Address = address,
                FirstTrustedUtc = now,
                LastValidatedUtc = now
            });
        }
        else
        {
            existing.Fingerprint = fingerprint;
            existing.Address = address;
            existing.LastValidatedUtc = now;
        }

        SaveDocument(document);
    }

    private static TrustDocument LoadDocument()
    {
        try
        {
            if (!File.Exists(TrustPath))
            {
                return new TrustDocument();
            }

            return JsonSerializer.Deserialize<TrustDocument>(File.ReadAllText(TrustPath), JsonOptions) ?? new TrustDocument();
        }
        catch
        {
            return new TrustDocument();
        }
    }

    private static void SaveDocument(TrustDocument document)
    {
        Directory.CreateDirectory(TrustDirectory);
        File.WriteAllText(TrustPath, JsonSerializer.Serialize(document, JsonOptions));
    }
}

