using System.Buffers.Binary;
using System.IO;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Windows;
using BlackbirdOperator.Models;

namespace BlackbirdOperator.Services;

internal sealed class SecureNodeCommandClient : IAsyncDisposable
{
    private const int UploadChunkBytes = 16 * 1024;
    private const string ClientHelloKind = "blackbird.operator.clientHello";
    private const string ServerHelloKind = "blackbird.node.serverHello";
    private const string ClientAuthKind = "blackbird.operator.clientAuth";
    private const string SecureEnvelopeKind = "blackbird.operator.secure";
    private const string HandshakeLabel = "BLACKBIRD_OPERATOR_HANDSHAKE_V1";
    private const string SessionKeyLabel = "BLACKBIRD_OPERATOR_SESSION_AES_V1";
    private const int CommandConnectTimeoutMs = 2500;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    private sealed class ClientHello
    {
        [JsonPropertyName("kind")]
        public string Kind { get; set; } = ClientHelloKind;

        [JsonPropertyName("protocol")]
        public int Protocol { get; set; } = 1;

        [JsonPropertyName("operatorId")]
        public string OperatorId { get; set; } = string.Empty;

        [JsonPropertyName("operatorFingerprint")]
        public string OperatorFingerprint { get; set; } = string.Empty;

        [JsonPropertyName("operatorIdentityPublic")]
        public string OperatorIdentityPublic { get; set; } = string.Empty;

        [JsonPropertyName("clientNonce")]
        public string ClientNonce { get; set; } = string.Empty;

        [JsonPropertyName("clientEcdhPublic")]
        public string ClientEcdhPublic { get; set; } = string.Empty;
    }

    private sealed class ServerHello
    {
        [JsonPropertyName("kind")]
        public string Kind { get; set; } = string.Empty;

        [JsonPropertyName("protocol")]
        public int Protocol { get; set; }

        [JsonPropertyName("nodeId")]
        public string NodeId { get; set; } = string.Empty;

        [JsonPropertyName("identityFingerprint")]
        public string IdentityFingerprint { get; set; } = string.Empty;

        [JsonPropertyName("identityPublic")]
        public string IdentityPublic { get; set; } = string.Empty;

        [JsonPropertyName("serverNonce")]
        public string ServerNonce { get; set; } = string.Empty;

        [JsonPropertyName("serverEcdhPublic")]
        public string ServerEcdhPublic { get; set; } = string.Empty;

        [JsonPropertyName("signature")]
        public string Signature { get; set; } = string.Empty;
    }

    private sealed class ClientAuth
    {
        [JsonPropertyName("kind")]
        public string Kind { get; set; } = ClientAuthKind;

        [JsonPropertyName("operatorFingerprint")]
        public string OperatorFingerprint { get; set; } = string.Empty;

        [JsonPropertyName("signature")]
        public string Signature { get; set; } = string.Empty;
    }

    private sealed class SecureEnvelope
    {
        [JsonPropertyName("kind")]
        public string Kind { get; set; } = SecureEnvelopeKind;

        [JsonPropertyName("seq")]
        public long Seq { get; set; }

        [JsonPropertyName("nonce")]
        public string Nonce { get; set; } = string.Empty;

        [JsonPropertyName("tag")]
        public string Tag { get; set; } = string.Empty;

        [JsonPropertyName("ciphertext")]
        public string Ciphertext { get; set; } = string.Empty;
    }

    private sealed class CommandRequest
    {
        [JsonPropertyName("command")]
        public string Command { get; set; } = string.Empty;

        [JsonPropertyName("payload")]
        public JsonElement? Payload { get; set; }
    }

    private sealed class CommandResponse
    {
        [JsonPropertyName("ok")]
        public bool Ok { get; set; }

        [JsonPropertyName("reply")]
        public string Reply { get; set; } = string.Empty;

        [JsonPropertyName("error")]
        public string Error { get; set; } = string.Empty;

        [JsonPropertyName("payload")]
        public JsonElement? Payload { get; set; }
    }

    private sealed class UploadStartPayload
    {
        [JsonPropertyName("jobId")]
        public string JobId { get; set; } = string.Empty;

        [JsonPropertyName("fileName")]
        public string FileName { get; set; } = string.Empty;

        [JsonPropertyName("totalBytes")]
        public long TotalBytes { get; set; }
    }

    private sealed class UploadChunkPayload
    {
        [JsonPropertyName("jobId")]
        public string JobId { get; set; } = string.Empty;

        [JsonPropertyName("chunkIndex")]
        public long ChunkIndex { get; set; }

        [JsonPropertyName("chunkBase64")]
        public string ChunkBase64 { get; set; } = string.Empty;
    }

    private sealed class AnalyzePayload
    {
        [JsonPropertyName("jobId")]
        public string JobId { get; set; } = string.Empty;
    }

    private sealed class DownloadPayload
    {
        [JsonPropertyName("jobId")]
        public string JobId { get; set; } = string.Empty;

        [JsonPropertyName("artifact")]
        public string Artifact { get; set; } = string.Empty;
    }

    private sealed class DownloadResultPayload
    {
        [JsonPropertyName("jobId")]
        public string JobId { get; set; } = string.Empty;

        [JsonPropertyName("artifact")]
        public string Artifact { get; set; } = string.Empty;

        [JsonPropertyName("fileBase64")]
        public string FileBase64 { get; set; } = string.Empty;

        [JsonPropertyName("size")]
        public int Size { get; set; }
    }

    internal sealed class RemoteAnalysisResult
    {
        public string JobId { get; init; } = string.Empty;
        public string FileName { get; init; } = string.Empty;
        public byte[] AnalysisJsonBytes { get; init; } = [];
    }

    private readonly TcpClient _client;
    private readonly NetworkStream _stream;
    private readonly StreamReader _reader;
    private readonly StreamWriter _writer;
    private readonly byte[] _sessionKey;
    private long _sendSequence;
    private long _receiveSequence;

    private SecureNodeCommandClient(TcpClient client, byte[] sessionKey)
    {
        _client = client;
        _stream = client.GetStream();
        _reader = new StreamReader(_stream, new UTF8Encoding(false), detectEncodingFromByteOrderMarks: false, leaveOpen: true);
        _writer = new StreamWriter(_stream, new UTF8Encoding(false), leaveOpen: true) { AutoFlush = true, NewLine = "\n" };
        _sessionKey = sessionKey;
    }

    public static async Task<SecureNodeCommandClient> ConnectAsync(OperatorNode node, Window? owner = null, CancellationToken cancellationToken = default)
    {
        if (node.CommandPort <= 0)
        {
            throw new InvalidOperationException("Node did not advertise a secure command port.");
        }

        OperatorIdentityStore.OperatorIdentity identity = OperatorIdentityStore.LoadOrCreate();
        using var ecdh = new ECDiffieHellmanCng(256)
        {
            KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash,
            HashAlgorithm = CngAlgorithm.Sha256
        };

        byte[] clientNonce = RandomNumberGenerator.GetBytes(32);
        byte[] clientEcdhPublic = ecdh.Key.Export(CngKeyBlobFormat.EccPublicBlob);

        var client = new TcpClient(AddressFamily.InterNetwork)
        {
            NoDelay = true
        };
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(TimeSpan.FromMilliseconds(CommandConnectTimeoutMs));
        try
        {
            await client.ConnectAsync(node.Address, node.CommandPort, timeoutCts.Token);
        }
        catch
        {
            client.Dispose();
            throw;
        }
        try
        {
            NetworkStream stream = client.GetStream();
            using var reader = new StreamReader(stream, new UTF8Encoding(false), detectEncodingFromByteOrderMarks: false, leaveOpen: true);
            using var writer = new StreamWriter(stream, new UTF8Encoding(false), leaveOpen: true) { AutoFlush = true, NewLine = "\n" };

            var hello = new ClientHello
            {
                OperatorId = identity.OperatorId,
                OperatorFingerprint = identity.Fingerprint,
                OperatorIdentityPublic = Convert.ToBase64String(identity.PublicBlob),
                ClientNonce = Convert.ToBase64String(clientNonce),
                ClientEcdhPublic = Convert.ToBase64String(clientEcdhPublic)
            };

            await writer.WriteLineAsync(JsonSerializer.Serialize(hello, JsonOptions));
            string? serverHelloLine = await reader.ReadLineAsync(timeoutCts.Token);
            if (string.IsNullOrWhiteSpace(serverHelloLine))
            {
                throw new InvalidOperationException("Secure node handshake failed: empty server hello.");
            }

            ServerHello serverHello = JsonSerializer.Deserialize<ServerHello>(serverHelloLine, JsonOptions)
                ?? throw new InvalidOperationException("Secure node handshake failed: invalid server hello.");
            if (!string.Equals(serverHello.Kind, ServerHelloKind, StringComparison.Ordinal))
            {
                throw new InvalidOperationException("Secure node handshake failed: unexpected server hello kind.");
            }

            byte[] nodeIdentityPublic = Convert.FromBase64String(serverHello.IdentityPublic);
            string presentedFingerprint = OperatorIdentityStore.ComputeFingerprint(nodeIdentityPublic);
            if (!string.Equals(presentedFingerprint, serverHello.IdentityFingerprint, StringComparison.OrdinalIgnoreCase))
            {
                throw new CryptographicException("Node identity fingerprint did not match the presented public key.");
            }
            if (!string.IsNullOrWhiteSpace(node.IdentityFingerprint) &&
                !string.Equals(node.IdentityFingerprint, presentedFingerprint, StringComparison.OrdinalIgnoreCase))
            {
                throw new CryptographicException("Node identity fingerprint changed between discovery and secure connect.");
            }

            OperatorTrustStore.NodeTrustEntry? trustEntry = OperatorTrustStore.Find(serverHello.NodeId);
            if (trustEntry is null)
            {
                MessageBoxResult trustResult = MessageBox.Show(
                    owner,
                    $"Blackbird node '{node.DisplayName}' at {node.Address} presented fingerprint:\n\n{presentedFingerprint}\n\nTrust this node for secure command and control?",
                    "Trust Blackbird Node",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Warning,
                    MessageBoxResult.No);
                if (trustResult != MessageBoxResult.Yes)
                {
                    throw new UnauthorizedAccessException("Operator trust was not granted for this node.");
                }

                OperatorTrustStore.SaveOrUpdate(serverHello.NodeId, presentedFingerprint, node.Address);
            }
            else if (!string.Equals(trustEntry.Fingerprint, presentedFingerprint, StringComparison.OrdinalIgnoreCase))
            {
                throw new CryptographicException("Node fingerprint does not match the pinned trust entry.");
            }
            else
            {
                OperatorTrustStore.SaveOrUpdate(serverHello.NodeId, presentedFingerprint, node.Address);
            }

            byte[] serverNonce = Convert.FromBase64String(serverHello.ServerNonce);
            byte[] serverEcdhPublic = Convert.FromBase64String(serverHello.ServerEcdhPublic);
            byte[] transcript = BuildTranscript(identity.Fingerprint, serverHello.NodeId, hello.ClientNonce, serverHello.ServerNonce, hello.ClientEcdhPublic, serverHello.ServerEcdhPublic);
            byte[] serverSignature = Convert.FromBase64String(serverHello.Signature);

            using (CngKey nodeVerifyKey = CngKey.Import(nodeIdentityPublic, CngKeyBlobFormat.EccPublicBlob))
            using (var verifier = new ECDsaCng(nodeVerifyKey))
            {
                if (!verifier.VerifyData(transcript, serverSignature, HashAlgorithmName.SHA256))
                {
                    throw new CryptographicException("Node handshake signature verification failed.");
                }
            }

            using CngKey peerEcdhKey = CngKey.Import(serverEcdhPublic, CngKeyBlobFormat.EccPublicBlob);
            byte[] secretMaterial = ecdh.DeriveKeyMaterial(peerEcdhKey);
            byte[] sessionKey = DeriveSessionKey(secretMaterial, clientNonce, serverNonce);

            byte[] clientSignature;
            using (CngKey operatorKey = CngKey.Import(identity.PrivateBlob, CngKeyBlobFormat.EccPrivateBlob))
            using (var signer = new ECDsaCng(operatorKey))
            {
                clientSignature = signer.SignData(transcript, HashAlgorithmName.SHA256);
            }

            var auth = new ClientAuth
            {
                OperatorFingerprint = identity.Fingerprint,
                Signature = Convert.ToBase64String(clientSignature)
            };
            await writer.WriteLineAsync(JsonSerializer.Serialize(auth, JsonOptions));

            var connected = new SecureNodeCommandClient(client, sessionKey);
            await connected.SendPingAsync(timeoutCts.Token);
            return connected;
        }
        catch
        {
            client.Dispose();
            throw;
        }
    }

    public async Task SendPingAsync(CancellationToken cancellationToken = default)
    {
        CommandResponse response = await SendCommandAsync("PING", null, cancellationToken);
        if (!response.Ok || !string.Equals(response.Reply, "PONG", StringComparison.Ordinal))
        {
            throw new InvalidOperationException(string.IsNullOrWhiteSpace(response.Error)
                ? "Secure node ping failed."
                : response.Error);
        }
    }

    public async Task<string> SendRawCommandAsync(string command, CancellationToken cancellationToken = default)
    {
        CommandResponse response = await SendCommandAsync(command, null, cancellationToken);
        if (response.Ok)
        {
            return string.IsNullOrWhiteSpace(response.Reply) ? "OK" : response.Reply;
        }
        return string.IsNullOrWhiteSpace(response.Error) ? "ERROR" : $"ERROR: {response.Error}";
    }

    public async Task<RemoteAnalysisResult> UploadFileForAnalysisAsync(string localPath, CancellationToken cancellationToken = default)
    {
        string fileName = Path.GetFileName(localPath);
        if (string.IsNullOrWhiteSpace(fileName))
        {
            throw new InvalidOperationException("A file name could not be derived from the selected path.");
        }

        byte[] fileBytes = await File.ReadAllBytesAsync(localPath, cancellationToken);
        string jobId = Guid.NewGuid().ToString("N");

        CommandResponse startResponse = await SendCommandAsync(
            "UPLOAD_FILE_START",
            JsonSerializer.SerializeToElement(new UploadStartPayload
            {
                JobId = jobId,
                FileName = fileName,
                TotalBytes = fileBytes.Length
            }, JsonOptions),
            cancellationToken);
        EnsureOk(startResponse, "Failed to start remote upload.");

        int chunkIndex = 0;
        for (int offset = 0; offset < fileBytes.Length; offset += UploadChunkBytes)
        {
            int remaining = Math.Min(UploadChunkBytes, fileBytes.Length - offset);
            byte[] chunk = new byte[remaining];
            Buffer.BlockCopy(fileBytes, offset, chunk, 0, remaining);
            CommandResponse chunkResponse = await SendCommandAsync(
                "UPLOAD_FILE_CHUNK",
                JsonSerializer.SerializeToElement(new UploadChunkPayload
                {
                    JobId = jobId,
                    ChunkIndex = chunkIndex++,
                    ChunkBase64 = Convert.ToBase64String(chunk)
                }, JsonOptions),
                cancellationToken);
            EnsureOk(chunkResponse, "Failed while sending file chunk to the node.");
        }

        CommandResponse analyzeResponse = await SendCommandAsync(
            "ANALYZE_UPLOADED_FILE",
            JsonSerializer.SerializeToElement(new AnalyzePayload { JobId = jobId }, JsonOptions),
            cancellationToken);
        EnsureOk(analyzeResponse, "The node did not generate an analysis artifact.");

        CommandResponse downloadResponse = await SendCommandAsync(
            "DOWNLOAD_FILE",
            JsonSerializer.SerializeToElement(new DownloadPayload { JobId = jobId, Artifact = "analysis.json" }, JsonOptions),
            cancellationToken);
        EnsureOk(downloadResponse, "The node did not return the generated analysis artifact.");

        DownloadResultPayload payload = RequirePayload<DownloadResultPayload>(downloadResponse, "The node returned an invalid analysis artifact payload.");
        return new RemoteAnalysisResult
        {
            JobId = jobId,
            FileName = fileName,
            AnalysisJsonBytes = Convert.FromBase64String(payload.FileBase64)
        };
    }

    private async Task<CommandResponse> SendCommandAsync(string command, JsonElement? payload, CancellationToken cancellationToken = default)
    {
        var request = new CommandRequest
        {
            Command = command,
            Payload = payload
        };

        byte[] plaintext = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(request, JsonOptions));
        long sequence = Interlocked.Increment(ref _sendSequence);
        SecureEnvelope envelope = EncryptEnvelope(sequence, plaintext, true);
        await _writer.WriteLineAsync(JsonSerializer.Serialize(envelope, JsonOptions));

        string? responseLine = await _reader.ReadLineAsync(cancellationToken);
        if (string.IsNullOrWhiteSpace(responseLine))
        {
            throw new IOException("Secure node response was empty.");
        }

        SecureEnvelope responseEnvelope = JsonSerializer.Deserialize<SecureEnvelope>(responseLine, JsonOptions)
            ?? throw new InvalidOperationException("Secure node response envelope was invalid.");
        byte[] responsePlaintext = DecryptEnvelope(responseEnvelope, false);
        CommandResponse? response = JsonSerializer.Deserialize<CommandResponse>(responsePlaintext, JsonOptions);
        return response ?? new CommandResponse { Ok = false, Error = "Secure node response was invalid." };
    }

    private static void EnsureOk(CommandResponse response, string fallbackMessage)
    {
        if (!response.Ok)
        {
            throw new InvalidOperationException(string.IsNullOrWhiteSpace(response.Error) ? fallbackMessage : response.Error);
        }
    }

    private static T RequirePayload<T>(CommandResponse response, string message)
    {
        if (response.Payload is not JsonElement payload || payload.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined)
        {
            throw new InvalidOperationException(message);
        }

        T? typed = payload.Deserialize<T>(JsonOptions);
        return typed ?? throw new InvalidOperationException(message);
    }

    private SecureEnvelope EncryptEnvelope(long sequence, byte[] plaintext, bool outbound)
    {
        byte[] nonce = BuildNonce(sequence, outbound);
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[16];
        using var aes = new AesGcm(_sessionKey, 16);
        aes.Encrypt(nonce, plaintext, ciphertext, tag, null);
        return new SecureEnvelope
        {
            Seq = sequence,
            Nonce = Convert.ToBase64String(nonce),
            Tag = Convert.ToBase64String(tag),
            Ciphertext = Convert.ToBase64String(ciphertext)
        };
    }

    private byte[] DecryptEnvelope(SecureEnvelope envelope, bool outbound)
    {
        long expected = Interlocked.Increment(ref _receiveSequence);
        if (envelope.Seq != expected)
        {
            throw new CryptographicException("Secure node response sequence was invalid.");
        }

        byte[] nonce = Convert.FromBase64String(envelope.Nonce);
        byte[] expectedNonce = BuildNonce(envelope.Seq, outbound);
        if (!nonce.AsSpan().SequenceEqual(expectedNonce))
        {
            throw new CryptographicException("Secure node response nonce was invalid.");
        }

        byte[] ciphertext = Convert.FromBase64String(envelope.Ciphertext);
        byte[] tag = Convert.FromBase64String(envelope.Tag);
        byte[] plaintext = new byte[ciphertext.Length];
        using var aes = new AesGcm(_sessionKey, 16);
        aes.Decrypt(nonce, ciphertext, tag, plaintext, null);
        return plaintext;
    }

    private static byte[] BuildTranscript(string operatorFingerprint, string nodeId, string clientNonceBase64, string serverNonceBase64, string clientEcdhPublicBase64, string serverEcdhPublicBase64)
    {
        string transcript = string.Join("\n",
            HandshakeLabel,
            operatorFingerprint,
            nodeId,
            clientNonceBase64,
            serverNonceBase64,
            clientEcdhPublicBase64,
            serverEcdhPublicBase64);
        return Encoding.UTF8.GetBytes(transcript);
    }

    private static byte[] DeriveSessionKey(byte[] secretMaterial, byte[] clientNonce, byte[] serverNonce)
    {
        byte[] label = Encoding.UTF8.GetBytes(SessionKeyLabel);
        byte[] material = new byte[secretMaterial.Length + clientNonce.Length + serverNonce.Length + label.Length];
        Buffer.BlockCopy(secretMaterial, 0, material, 0, secretMaterial.Length);
        Buffer.BlockCopy(clientNonce, 0, material, secretMaterial.Length, clientNonce.Length);
        Buffer.BlockCopy(serverNonce, 0, material, secretMaterial.Length + clientNonce.Length, serverNonce.Length);
        Buffer.BlockCopy(label, 0, material, secretMaterial.Length + clientNonce.Length + serverNonce.Length, label.Length);
        return SHA256.HashData(material);
    }

    private static byte[] BuildNonce(long sequence, bool outbound)
    {
        var nonce = new byte[12];
        nonce[0] = outbound ? (byte)'C' : (byte)'S';
        BinaryPrimitives.WriteInt64BigEndian(nonce.AsSpan(4), sequence);
        return nonce;
    }

    public async ValueTask DisposeAsync()
    {
        try
        {
            await _writer.FlushAsync();
        }
        catch
        {
        }

        _reader.Dispose();
        _writer.Dispose();
        await _stream.DisposeAsync();
        _client.Dispose();
    }
}


