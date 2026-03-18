using System.IO;
using System.Security.Cryptography;
using System.Text.Json;

namespace BlackbirdOperator.Services;

internal static class OperatorIdentityStore
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true
    };

    private sealed class IdentityMetadata
    {
        public string OperatorId { get; set; } = string.Empty;
        public string Fingerprint { get; set; } = string.Empty;
        public string PublicKeyBase64 { get; set; } = string.Empty;
    }

    internal sealed class OperatorIdentity
    {
        public string OperatorId { get; init; } = string.Empty;
        public string Fingerprint { get; init; } = string.Empty;
        public byte[] PrivateBlob { get; init; } = [];
        public byte[] PublicBlob { get; init; } = [];
    }

    public static string IdentityDirectory => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Blackbird",
        "Operator",
        "identity");

    private static string PrivateKeyPath => Path.Combine(IdentityDirectory, "operator-identity.eccpriv");
    private static string MetadataPath => Path.Combine(IdentityDirectory, "operator-identity.json");

    public static OperatorIdentity LoadOrCreate()
    {
        try
        {
            if (File.Exists(PrivateKeyPath))
            {
                byte[] privateBlob = File.ReadAllBytes(PrivateKeyPath);
                byte[] publicBlob;
                using (CngKey privateKey = CngKey.Import(privateBlob, CngKeyBlobFormat.EccPrivateBlob))
                {
                    publicBlob = privateKey.Export(CngKeyBlobFormat.EccPublicBlob);
                }

                string fingerprint = ComputeFingerprint(publicBlob);
                string operatorId = LoadOperatorIdOrDefault(fingerprint, publicBlob);
                EnsureMetadata(operatorId, fingerprint, publicBlob);
                return new OperatorIdentity
                {
                    OperatorId = operatorId,
                    Fingerprint = fingerprint,
                    PrivateBlob = privateBlob,
                    PublicBlob = publicBlob
                };
            }
        }
        catch
        {
        }

        Directory.CreateDirectory(IdentityDirectory);
        using CngKey key = CngKey.Create(CngAlgorithm.ECDsaP256);
        byte[] createdPrivateBlob = key.Export(CngKeyBlobFormat.EccPrivateBlob);
        byte[] createdPublicBlob = key.Export(CngKeyBlobFormat.EccPublicBlob);
        string createdFingerprint = ComputeFingerprint(createdPublicBlob);
        string createdOperatorId = $"operator-{Environment.MachineName}";
        File.WriteAllBytes(PrivateKeyPath, createdPrivateBlob);
        EnsureMetadata(createdOperatorId, createdFingerprint, createdPublicBlob);
        return new OperatorIdentity
        {
            OperatorId = createdOperatorId,
            Fingerprint = createdFingerprint,
            PrivateBlob = createdPrivateBlob,
            PublicBlob = createdPublicBlob
        };
    }

    public static string ComputeFingerprint(byte[] publicBlob)
    {
        byte[] hash = SHA256.HashData(publicBlob);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private static string LoadOperatorIdOrDefault(string fingerprint, byte[] publicBlob)
    {
        try
        {
            if (File.Exists(MetadataPath))
            {
                IdentityMetadata? metadata = JsonSerializer.Deserialize<IdentityMetadata>(File.ReadAllText(MetadataPath), JsonOptions);
                if (metadata is not null &&
                    string.Equals(metadata.Fingerprint, fingerprint, StringComparison.OrdinalIgnoreCase))
                {
                    return string.IsNullOrWhiteSpace(metadata.OperatorId) ? $"operator-{Environment.MachineName}" : metadata.OperatorId;
                }
            }
        }
        catch
        {
        }

        EnsureMetadata($"operator-{Environment.MachineName}", fingerprint, publicBlob);
        return $"operator-{Environment.MachineName}";
    }

    private static void EnsureMetadata(string operatorId, string fingerprint, byte[] publicBlob)
    {
        Directory.CreateDirectory(IdentityDirectory);
        var metadata = new IdentityMetadata
        {
            OperatorId = operatorId,
            Fingerprint = fingerprint,
            PublicKeyBase64 = Convert.ToBase64String(publicBlob)
        };
        File.WriteAllText(MetadataPath, JsonSerializer.Serialize(metadata, JsonOptions));
    }
}

