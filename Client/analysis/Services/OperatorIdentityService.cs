using System;
using System.IO;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace BlackbirdInterface
{
    internal static class OperatorIdentityService
    {
        private const uint EcdsaPublicP256Magic = 0x31534345;
        private const uint EcdsaPrivateP256Magic = 0x32534345;
        private static readonly Regex FingerprintPattern = new("^[0-9a-fA-F]{64}$", RegexOptions.Compiled);

        public sealed class OperatorIdentityResult
        {
            public string IdentityPath { get; init; } = string.Empty;
            public string Fingerprint { get; init; } = string.Empty;
            public bool Created { get; init; }
        }

        public static OperatorIdentityResult EnsureIdentity()
        {
            return EnsureIdentity(GetDefaultIdentityPath(), $"BK-operator-{Environment.MachineName}");
        }

        public static OperatorIdentityResult EnsureServerIdentity(string blackbirdRoot)
        {
            string identityPath =
                Path.Combine(blackbirdRoot, "Server", "data", "operator-identity", "server-operator-identity.json");
            return EnsureIdentity(identityPath, $"BK-server-{Environment.MachineName}");
        }

        private static OperatorIdentityResult EnsureIdentity(string identityPath, string operatorId)
        {
            string existingFingerprint = TryReadFingerprint(identityPath);
            if (IsFingerprint(existingFingerprint))
            {
                return new OperatorIdentityResult { IdentityPath = identityPath,
                                                    Fingerprint = existingFingerprint.ToLowerInvariant(),
                                                    Created = false };
            }

            Directory.CreateDirectory(Path.GetDirectoryName(identityPath)!);

            using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            ECParameters parameters = key.ExportParameters(includePrivateParameters: true);
            byte[] publicBlob = CreateCngBlob(parameters, includePrivate: false);
            byte[] privateBlob = CreateCngBlob(parameters, includePrivate: true);
            byte[] pkcs8 = key.ExportPkcs8PrivateKey();
            string fingerprint = Convert.ToHexString(SHA256.HashData(publicBlob)).ToLowerInvariant();

            var identity = new { protocol = 1,
                                 kind = "BK.operator.identity",
                                 operator_id = operatorId,
                                 curve = "ECDSA_P256",
                                 createdUtc = DateTime.UtcNow.ToString("o"),
                                 fingerprint,
                                 pkcs8_base64 = Convert.ToBase64String(pkcs8),
                                 public_key_base64 = Convert.ToBase64String(publicBlob),
                                 publicBlob = Convert.ToBase64String(publicBlob),
                                 privateBlob = Convert.ToBase64String(privateBlob) };

            File.WriteAllText(identityPath,
                              JsonSerializer.Serialize(identity, new JsonSerializerOptions { WriteIndented = true }));

            return new OperatorIdentityResult { IdentityPath = identityPath, Fingerprint = fingerprint,
                                                Created = true };
        }

        private static string GetDefaultIdentityPath()
        {
            string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            if (string.IsNullOrWhiteSpace(localAppData))
            {
                localAppData = AppContext.BaseDirectory;
            }

            return Path.Combine(localAppData, "BK", "Operator", "identity.json");
        }

        private static string TryReadFingerprint(string identityPath)
        {
            try
            {
                if (!File.Exists(identityPath))
                {
                    return string.Empty;
                }

                using JsonDocument document = JsonDocument.Parse(File.ReadAllText(identityPath));
                if (document.RootElement.TryGetProperty("fingerprint", out JsonElement fingerprintElement) &&
                    TryGetPublicBlobElement(document.RootElement, out JsonElement publicBlobElement))
                {
                    string? fingerprint = fingerprintElement.GetString();
                    string? publicBlobBase64 = publicBlobElement.GetString();
                    if (!IsFingerprint(fingerprint) || string.IsNullOrWhiteSpace(publicBlobBase64))
                    {
                        return string.Empty;
                    }

                    byte[] publicBlob = Convert.FromBase64String(publicBlobBase64);
                    if (publicBlob.Length != 72)
                    {
                        return string.Empty;
                    }

                    string computed = Convert.ToHexString(SHA256.HashData(publicBlob)).ToLowerInvariant();
                    return string.Equals(computed, fingerprint, StringComparison.OrdinalIgnoreCase) ? computed
                                                                                                    : string.Empty;
                }
            }
            catch
            {
                return string.Empty;
            }

            return string.Empty;
        }

        private static bool IsFingerprint(string? value)
        {
            return !string.IsNullOrWhiteSpace(value) && FingerprintPattern.IsMatch(value);
        }

        private static bool TryGetPublicBlobElement(JsonElement root, out JsonElement publicBlobElement)
        {
            if (root.TryGetProperty("public_key_base64", out publicBlobElement))
            {
                return true;
            }

            return root.TryGetProperty("publicBlob", out publicBlobElement);
        }

        private static byte[] CreateCngBlob(ECParameters parameters, bool includePrivate)
        {
            byte[] x = ToFixed32(parameters.Q.X);
            byte[] y = ToFixed32(parameters.Q.Y);
            byte[]? d = includePrivate ? ToFixed32(parameters.D) : null;
            byte[] blob = new byte[8 + x.Length + y.Length + (d?.Length ?? 0)];

            WriteUInt32(blob, 0, includePrivate ? EcdsaPrivateP256Magic : EcdsaPublicP256Magic);
            WriteUInt32(blob, 4, 32);
            Buffer.BlockCopy(x, 0, blob, 8, x.Length);
            Buffer.BlockCopy(y, 0, blob, 40, y.Length);
            if (d is not null)
            {
                Buffer.BlockCopy(d, 0, blob, 72, d.Length);
            }

            return blob;
        }

        private static byte[] ToFixed32(byte[]? value)
        {
            if (value is null || value.Length == 0 || value.Length > 32)
            {
                throw new InvalidOperationException("Unexpected P-256 key material length.");
            }

            byte[] result = new byte[32];
            Buffer.BlockCopy(value, 0, result, 32 - value.Length, value.Length);
            return result;
        }

        private static void WriteUInt32(byte[] buffer, int offset, uint value)
        {
            buffer[offset] = (byte)(value & 0xff);
            buffer[offset + 1] = (byte)((value >> 8) & 0xff);
            buffer[offset + 2] = (byte)((value >> 16) & 0xff);
            buffer[offset + 3] = (byte)((value >> 24) & 0xff);
        }
    }
}
