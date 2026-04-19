#include "../blackbird_controller_private.h"

typedef LONG(WINAPI *BLACKBIRD_RTLGETVERSION_FN)(_Inout_ PRTL_OSVERSIONINFOW);

#define BLACKBIRD_NODE_IDENTITY_PUBLIC_BLOB_CAPACITY 256u
#define BLACKBIRD_NODE_IDENTITY_PRIVATE_BLOB_CAPACITY 256u
#define BLACKBIRD_NODE_FINGERPRINT_CHARS 65u
#define BLACKBIRD_NODE_HANDSHAKE_LABEL "BLACKBIRD_OPERATOR_HANDSHAKE_V1"
#define BLACKBIRD_NODE_SESSION_LABEL "BLACKBIRD_OPERATOR_SESSION_AES_V1"
#define BLACKBIRD_NODE_CLIENT_HELLO_KIND "blackbird.operator.clientHello"
#define BLACKBIRD_NODE_SERVER_HELLO_KIND "blackbird.node.serverHello"
#define BLACKBIRD_NODE_CLIENT_AUTH_KIND "blackbird.operator.clientAuth"
#define BLACKBIRD_NODE_SECURE_KIND "blackbird.operator.secure"
#define BLACKBIRD_NODE_STATUS_QUERY "BLACKBIRD_STATUS_V1"
#define BLACKBIRD_NODE_NONCE_BYTES 12u
#define BLACKBIRD_NODE_TAG_BYTES 16u
#define BLACKBIRD_NODE_SESSION_KEY_BYTES 32u
#define BLACKBIRD_NODE_COMMAND_RECV_TIMEOUT_MS 2500u
#define BLACKBIRD_NODE_COMMAND_SEND_TIMEOUT_MS 2500u
#define BLACKBIRD_NODE_MAX_COMMAND_PLAINTEXT 49152u
#define BLACKBIRD_NODE_MAX_ENVELOPE_JSON 98304u
#define BLACKBIRD_NODE_MAX_UPLOAD_BYTES (4u * 1024u * 1024u)
#define BLACKBIRD_NODE_UPLOAD_CHUNK_BYTES 16384u

typedef struct _BLACKBIRD_NODE_SECURE_SESSION
{
    BYTE SessionKey[BLACKBIRD_NODE_SESSION_KEY_BYTES];
    ULONGLONG ExpectedInboundSequence;
    ULONGLONG OutboundSequence;
} BLACKBIRD_NODE_SECURE_SESSION, *PBLACKBIRD_NODE_SECURE_SESSION;

static volatile LONG g_NodeNetworkStarted = 0;
static HANDLE g_NodeBeaconThread = NULL;
static HANDLE g_NodeStatusThread = NULL;
static HANDLE g_NodeCommandThread = NULL;
static SOCKET g_NodeBeaconSocket = INVALID_SOCKET;
static SOCKET g_NodeStatusSocket = INVALID_SOCKET;
static SOCKET g_NodeCommandSocket = INVALID_SOCKET;
static OwnedCriticalSection g_NodeIdentityLock;
static BYTE g_NodeIdentityPrivateBlob[BLACKBIRD_NODE_IDENTITY_PRIVATE_BLOB_CAPACITY];
static ULONG g_NodeIdentityPrivateBlobLength = 0;
static BYTE g_NodeIdentityPublicBlob[BLACKBIRD_NODE_IDENTITY_PUBLIC_BLOB_CAPACITY];
static ULONG g_NodeIdentityPublicBlobLength = 0;
static CHAR g_NodeIdentityFingerprint[BLACKBIRD_NODE_FINGERPRINT_CHARS] = {0};
static const CHAR g_NodeStatusQuery[] = BLACKBIRD_NODE_STATUS_QUERY;

static BOOL ControllerNodeIsSocketValid(_In_ SOCKET value)
{
    return (value != INVALID_SOCKET);
}

static VOID ControllerNodeCloseSocket(_Inout_ SOCKET *value)
{
    if (value != NULL && ControllerNodeIsSocketValid(*value))
    {
        closesocket(*value);
        *value = INVALID_SOCKET;
    }
}

static VOID ControllerNodeSleepInterruptible(_In_ DWORD milliseconds)
{
    DWORD waited = 0;

    while (waited < milliseconds && !ControllerShouldStop())
    {
        DWORD slice = ((milliseconds - waited) > 200u) ? 200u : (milliseconds - waited);
        Sleep(slice);
        waited += slice;
    }
}

static BOOL ControllerNodeIsPrivateIpv4(_In_ const struct sockaddr_in *address)
{
    ULONG hostOrder;
    BYTE first;
    BYTE second;

    if (address == NULL || address->sin_family != AF_INET)
    {
        return FALSE;
    }

    hostOrder = ntohl(address->sin_addr.S_un.S_addr);
    first = (BYTE)((hostOrder >> 24) & 0xFFu);
    second = (BYTE)((hostOrder >> 16) & 0xFFu);

    if (first == 10u || first == 127u)
    {
        return TRUE;
    }
    if (first == 192u && second == 168u)
    {
        return TRUE;
    }
    if (first == 172u && second >= 16u && second <= 31u)
    {
        return TRUE;
    }
    if (first == 169u && second == 254u)
    {
        return TRUE;
    }

    return FALSE;
}

static VOID ControllerNodeUtf8FromWide(_In_opt_z_ PCWSTR source, _Out_writes_z_(destinationChars) PSTR destination,
                                       _In_ size_t destinationChars)
{
    int written;

    if (destination == NULL || destinationChars == 0)
    {
        return;
    }

    destination[0] = '\0';
    if (source == NULL || source[0] == L'\0')
    {
        return;
    }

    written = WideCharToMultiByte(CP_UTF8, 0, source, -1, destination, (int)destinationChars, NULL, NULL);
    if (written <= 0)
    {
        destination[0] = '\0';
    }
}

static VOID ControllerNodeGetComputerNameUtf8(_Out_writes_z_(destinationChars) PSTR destination,
                                              _In_ size_t destinationChars)
{
    WCHAR buffer[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD chars = RTL_NUMBER_OF(buffer);

    if (!GetComputerNameExW(ComputerNamePhysicalDnsHostname, buffer, &chars))
    {
        chars = RTL_NUMBER_OF(buffer);
        if (!GetComputerNameW(buffer, &chars))
        {
            buffer[0] = L'\0';
        }
    }

    ControllerNodeUtf8FromWide(buffer, destination, destinationChars);
}

static VOID ControllerNodeGetVersionString(_Out_writes_z_(destinationChars) PSTR destination,
                                           _In_ size_t destinationChars)
{
    RTL_OSVERSIONINFOW versionInfo;
    BLACKBIRD_RTLGETVERSION_FN rtlGetVersion;
    HMODULE ntdll;

    if (destination == NULL || destinationChars == 0)
    {
        return;
    }

    destination[0] = '\0';
    ZeroMemory(&versionInfo, sizeof(versionInfo));
    versionInfo.dwOSVersionInfoSize = sizeof(versionInfo);

    ntdll = GetModuleHandleW(L"ntdll.dll");
    rtlGetVersion = (ntdll != NULL) ? (BLACKBIRD_RTLGETVERSION_FN)GetProcAddress(ntdll, "RtlGetVersion") : NULL;
    if (rtlGetVersion != NULL && rtlGetVersion(&versionInfo) == 0)
    {
        (void)StringCchPrintfA(destination, destinationChars, "%lu.%lu.%lu", versionInfo.dwMajorVersion,
                               versionInfo.dwMinorVersion, versionInfo.dwBuildNumber);
        return;
    }

#pragma warning(push)
#pragma warning(disable : 4996)
    if (GetVersionExW((LPOSVERSIONINFOW)&versionInfo))
    {
        (void)StringCchPrintfA(destination, destinationChars, "%lu.%lu.%lu", versionInfo.dwMajorVersion,
                               versionInfo.dwMinorVersion, versionInfo.dwBuildNumber);
        return;
    }
#pragma warning(pop)

    (void)StringCchCopyA(destination, destinationChars, "unknown");
}

static VOID ControllerNodeFormatUtcNow(_Out_writes_z_(destinationChars) PSTR destination, _In_ size_t destinationChars)
{
    SYSTEMTIME systemTime;

    if (destination == NULL || destinationChars == 0)
    {
        return;
    }

    GetSystemTime(&systemTime);
    (void)StringCchPrintfA(destination, destinationChars, "%04u-%02u-%02uT%02u:%02u:%02uZ", systemTime.wYear,
                           systemTime.wMonth, systemTime.wDay, systemTime.wHour, systemTime.wMinute,
                           systemTime.wSecond);
}

static BOOL ControllerNodeEnsureIdentityLock(VOID)
{
    return TRUE;
}

static BOOL ControllerNodeBuildProgramDataPath(_Out_writes_z_(destinationChars) PWSTR destination,
                                               _In_ size_t destinationChars, _In_opt_z_ PCWSTR suffix)
{
    WCHAR programData[MAX_PATH];
    DWORD copied;

    if (destination == NULL || destinationChars == 0)
    {
        return FALSE;
    }

    copied = GetEnvironmentVariableW(L"ProgramData", programData, RTL_NUMBER_OF(programData));
    if (copied == 0 || copied >= RTL_NUMBER_OF(programData))
    {
        return FALSE;
    }

    if (suffix != NULL && suffix[0] != L'\0')
    {
        return SUCCEEDED(
            StringCchPrintfW(destination, destinationChars, L"%s\\Blackbird\\Node\\%s", programData, suffix));
    }

    return SUCCEEDED(StringCchPrintfW(destination, destinationChars, L"%s\\Blackbird\\Node", programData));
}

static BOOL ControllerNodeEnsureDirectory(_In_z_ PCWSTR path)
{
    return (CreateDirectoryW(path, NULL) || GetLastError() == ERROR_ALREADY_EXISTS);
}

static BOOL ControllerNodeEnsureStorageDirectories(VOID)
{
    WCHAR path[MAX_PATH];
    WCHAR programData[MAX_PATH];
    DWORD copied = GetEnvironmentVariableW(L"ProgramData", programData, RTL_NUMBER_OF(programData));

    if (copied == 0 || copied >= RTL_NUMBER_OF(programData))
    {
        return FALSE;
    }

    if (!ControllerNodeEnsureDirectory(programData))
    {
        return FALSE;
    }
    if (FAILED(StringCchPrintfW(path, RTL_NUMBER_OF(path), L"%s\\Blackbird", programData)) ||
        !ControllerNodeEnsureDirectory(path))
    {
        return FALSE;
    }
    if (!ControllerNodeBuildProgramDataPath(path, RTL_NUMBER_OF(path), NULL) || !ControllerNodeEnsureDirectory(path))
    {
        return FALSE;
    }
    if (!ControllerNodeBuildProgramDataPath(path, RTL_NUMBER_OF(path), L"identity") ||
        !ControllerNodeEnsureDirectory(path))
    {
        return FALSE;
    }
    if (!ControllerNodeBuildProgramDataPath(path, RTL_NUMBER_OF(path), L"trust") ||
        !ControllerNodeEnsureDirectory(path))
    {
        return FALSE;
    }
    if (!ControllerNodeBuildProgramDataPath(path, RTL_NUMBER_OF(path), L"jobs") || !ControllerNodeEnsureDirectory(path))
    {
        return FALSE;
    }

    return TRUE;
}

static BOOL ControllerNodeReadSmallFile(_In_z_ PCWSTR path, _Out_writes_bytes_(bufferCapacity) PBYTE buffer,
                                        _In_ DWORD bufferCapacity, _Out_ DWORD *bytesRead)
{
    HANDLE fileHandle;
    DWORD localRead = 0;
    BOOL result;

    if (bytesRead != NULL)
    {
        *bytesRead = 0;
    }

    fileHandle = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (fileHandle == INVALID_HANDLE_VALUE)
    {
        return FALSE;
    }

    result = ReadFile(fileHandle, buffer, bufferCapacity, &localRead, NULL);
    CloseHandle(fileHandle);
    if (!result)
    {
        return FALSE;
    }

    if (bytesRead != NULL)
    {
        *bytesRead = localRead;
    }
    return TRUE;
}

static BOOL ControllerNodeWriteSmallFile(_In_z_ PCWSTR path, _In_reads_bytes_(bytesToWrite) const BYTE *buffer,
                                         _In_ DWORD bytesToWrite)
{
    HANDLE fileHandle;
    DWORD written = 0;
    BOOL result;

    fileHandle = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
    if (fileHandle == INVALID_HANDLE_VALUE)
    {
        return FALSE;
    }

    result = WriteFile(fileHandle, buffer, bytesToWrite, &written, NULL);
    CloseHandle(fileHandle);
    return (result && written == bytesToWrite);
}

static BOOL ControllerNodeAppendFile(_In_z_ PCWSTR path, _In_reads_bytes_(bytesToWrite) const BYTE *buffer,
                                     _In_ DWORD bytesToWrite)
{
    HANDLE fileHandle;
    DWORD written = 0;
    BOOL result;

    fileHandle = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (fileHandle == INVALID_HANDLE_VALUE)
    {
        return FALSE;
    }

    result = WriteFile(fileHandle, buffer, bytesToWrite, &written, NULL);
    CloseHandle(fileHandle);
    return (result && written == bytesToWrite);
}

static BOOL ControllerNodeComputeSha256(_In_reads_bytes_(dataLength) const BYTE *data, _In_ ULONG dataLength,
                                        _Out_writes_bytes_(32) PBYTE hash)
{
    BCRYPT_ALG_HANDLE algorithm = NULL;
    BCRYPT_HASH_HANDLE hashHandle = NULL;
    PUCHAR hashObject = NULL;
    DWORD objectLength = 0;
    DWORD bytesCopied = 0;
    NTSTATUS status;
    BOOL success = FALSE;

    status = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status))
    {
        return FALSE;
    }

    status = BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objectLength, sizeof(objectLength),
                               &bytesCopied, 0);
    if (!BCRYPT_SUCCESS(status) || objectLength == 0)
    {
        goto Cleanup;
    }

    hashObject = (PUCHAR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, objectLength);
    if (hashObject == NULL)
    {
        goto Cleanup;
    }

    status = BCryptCreateHash(algorithm, &hashHandle, hashObject, objectLength, NULL, 0, 0);
    if (!BCRYPT_SUCCESS(status))
    {
        goto Cleanup;
    }

    status = BCryptHashData(hashHandle, (PUCHAR)data, dataLength, 0);
    if (!BCRYPT_SUCCESS(status))
    {
        goto Cleanup;
    }

    status = BCryptFinishHash(hashHandle, hash, 32u, 0);
    if (!BCRYPT_SUCCESS(status))
    {
        goto Cleanup;
    }

    success = TRUE;

Cleanup:
    if (hashHandle != NULL)
    {
        BCryptDestroyHash(hashHandle);
    }
    if (hashObject != NULL)
    {
        HeapFree(GetProcessHeap(), 0, hashObject);
    }
    if (algorithm != NULL)
    {
        BCryptCloseAlgorithmProvider(algorithm, 0);
    }

    return success;
}

static BOOL ControllerNodeComputeFingerprint(_In_reads_bytes_(publicBlobLength) const BYTE *publicBlob,
                                             _In_ ULONG publicBlobLength,
                                             _Out_writes_z_(fingerprintChars) PSTR fingerprint,
                                             _In_ size_t fingerprintChars)
{
    BYTE hash[32];
    size_t index;

    if (fingerprint == NULL || fingerprintChars < BLACKBIRD_NODE_FINGERPRINT_CHARS ||
        !ControllerNodeComputeSha256(publicBlob, publicBlobLength, hash))
    {
        return FALSE;
    }

    fingerprint[0] = '\0';
    for (index = 0; index < 32u; index++)
    {
        (void)StringCchPrintfA(fingerprint + (index * 2u), fingerprintChars - (index * 2u), "%02x", hash[index]);
    }

    return TRUE;
}
static BOOL ControllerNodeGenerateIdentity(
    _Out_writes_bytes_(BLACKBIRD_NODE_IDENTITY_PRIVATE_BLOB_CAPACITY) PBYTE privateBlob, _Out_ PULONG privateBlobLength,
    _Out_writes_bytes_(BLACKBIRD_NODE_IDENTITY_PUBLIC_BLOB_CAPACITY) PBYTE publicBlob, _Out_ PULONG publicBlobLength)
{
    BCRYPT_ALG_HANDLE algorithm = NULL;
    BCRYPT_KEY_HANDLE keyHandle = NULL;
    NTSTATUS status;
    BOOL success = FALSE;

    status = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_ECDSA_P256_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status))
    {
        return FALSE;
    }

    status = BCryptGenerateKeyPair(algorithm, &keyHandle, 256u, 0);
    if (!BCRYPT_SUCCESS(status))
    {
        goto Cleanup;
    }

    status = BCryptFinalizeKeyPair(keyHandle, 0);
    if (!BCRYPT_SUCCESS(status))
    {
        goto Cleanup;
    }

    status = BCryptExportKey(keyHandle, NULL, BCRYPT_ECCPRIVATE_BLOB, privateBlob,
                             BLACKBIRD_NODE_IDENTITY_PRIVATE_BLOB_CAPACITY, privateBlobLength, 0);
    if (!BCRYPT_SUCCESS(status))
    {
        goto Cleanup;
    }

    status = BCryptExportKey(keyHandle, NULL, BCRYPT_ECCPUBLIC_BLOB, publicBlob,
                             BLACKBIRD_NODE_IDENTITY_PUBLIC_BLOB_CAPACITY, publicBlobLength, 0);
    if (!BCRYPT_SUCCESS(status))
    {
        goto Cleanup;
    }

    success = TRUE;

Cleanup:
    if (keyHandle != NULL)
    {
        BCryptDestroyKey(keyHandle);
    }
    if (algorithm != NULL)
    {
        BCryptCloseAlgorithmProvider(algorithm, 0);
    }

    return success;
}

static BOOL ControllerNodeEnsureIdentityLoaded(VOID)
{
    WCHAR privatePath[MAX_PATH];
    WCHAR publicPath[MAX_PATH];
    BYTE privateBlob[BLACKBIRD_NODE_IDENTITY_PRIVATE_BLOB_CAPACITY];
    BYTE publicBlob[BLACKBIRD_NODE_IDENTITY_PUBLIC_BLOB_CAPACITY];
    DWORD privateBytes = 0;
    DWORD publicBytes = 0;
    ULONG privateBlobLength = 0;
    ULONG publicBlobLength = 0;
    CHAR fingerprint[BLACKBIRD_NODE_FINGERPRINT_CHARS] = {0};
    BOOL success = FALSE;

    if (!ControllerNodeEnsureIdentityLock() || !ControllerNodeEnsureStorageDirectories())
    {
        return FALSE;
    }

    EnterCriticalSection(g_NodeIdentityLock.get());
    if (g_NodeIdentityPublicBlobLength != 0 && g_NodeIdentityPrivateBlobLength != 0 &&
        g_NodeIdentityFingerprint[0] != '\0')
    {
        LeaveCriticalSection(g_NodeIdentityLock.get());
        return TRUE;
    }

    if (!ControllerNodeBuildProgramDataPath(privatePath, RTL_NUMBER_OF(privatePath),
                                            L"identity\\node-identity.eccpriv") ||
        !ControllerNodeBuildProgramDataPath(publicPath, RTL_NUMBER_OF(publicPath), L"identity\\node-identity.eccpub"))
    {
        LeaveCriticalSection(g_NodeIdentityLock.get());
        return FALSE;
    }

    if (ControllerNodeReadSmallFile(privatePath, privateBlob, sizeof(privateBlob), &privateBytes) &&
        ControllerNodeReadSmallFile(publicPath, publicBlob, sizeof(publicBlob), &publicBytes) && privateBytes != 0 &&
        publicBytes != 0)
    {
        privateBlobLength = privateBytes;
        publicBlobLength = publicBytes;
    }
    else if (!ControllerNodeGenerateIdentity(privateBlob, &privateBlobLength, publicBlob, &publicBlobLength) ||
             !ControllerNodeWriteSmallFile(privatePath, privateBlob, privateBlobLength) ||
             !ControllerNodeWriteSmallFile(publicPath, publicBlob, publicBlobLength))
    {
        LeaveCriticalSection(g_NodeIdentityLock.get());
        return FALSE;
    }

    if (!ControllerNodeComputeFingerprint(publicBlob, publicBlobLength, fingerprint, RTL_NUMBER_OF(fingerprint)))
    {
        LeaveCriticalSection(g_NodeIdentityLock.get());
        return FALSE;
    }

    CopyMemory(g_NodeIdentityPrivateBlob, privateBlob, privateBlobLength);
    g_NodeIdentityPrivateBlobLength = privateBlobLength;
    CopyMemory(g_NodeIdentityPublicBlob, publicBlob, publicBlobLength);
    g_NodeIdentityPublicBlobLength = publicBlobLength;
    (void)StringCchCopyA(g_NodeIdentityFingerprint, RTL_NUMBER_OF(g_NodeIdentityFingerprint), fingerprint);
    success = TRUE;
    LeaveCriticalSection(g_NodeIdentityLock.get());

    return success;
}

static BOOL ControllerNodeGetTrustedOperatorFingerprint(_Out_writes_z_(fingerprintChars) PSTR fingerprint,
                                                        _In_ size_t fingerprintChars)
{
    WCHAR trustPath[MAX_PATH];
    CHAR buffer[BLACKBIRD_NODE_FINGERPRINT_CHARS + 8];
    DWORD bytesRead = 0;
    size_t length;

    if (fingerprint == NULL || fingerprintChars == 0 ||
        !ControllerNodeBuildProgramDataPath(trustPath, RTL_NUMBER_OF(trustPath), L"trust\\trusted-operator.txt"))
    {
        return FALSE;
    }

    if (!ControllerNodeReadSmallFile(trustPath, (PBYTE)buffer, sizeof(buffer) - 1u, &bytesRead) || bytesRead == 0)
    {
        return FALSE;
    }

    buffer[bytesRead] = '\0';
    length = strlen(buffer);
    while (length != 0 && (buffer[length - 1u] == '\r' || buffer[length - 1u] == '\n' || buffer[length - 1u] == ' '))
    {
        buffer[length - 1u] = '\0';
        length--;
    }

    return SUCCEEDED(StringCchCopyA(fingerprint, fingerprintChars, buffer));
}

static BOOL ControllerNodePinTrustedOperatorFingerprint(_In_z_ PCSTR fingerprint)
{
    WCHAR trustPath[MAX_PATH];

    if (fingerprint == NULL || fingerprint[0] == '\0' ||
        !ControllerNodeBuildProgramDataPath(trustPath, RTL_NUMBER_OF(trustPath), L"trust\\trusted-operator.txt"))
    {
        return FALSE;
    }

    return ControllerNodeWriteSmallFile(trustPath, (const BYTE *)fingerprint, (DWORD)strlen(fingerprint));
}

static BOOL ControllerNodeEnsureTrustedOperator(_In_z_ PCSTR fingerprint)
{
    CHAR trusted[BLACKBIRD_NODE_FINGERPRINT_CHARS] = {0};

    if (fingerprint == NULL || fingerprint[0] == '\0')
    {
        return FALSE;
    }

    if (!ControllerNodeGetTrustedOperatorFingerprint(trusted, RTL_NUMBER_OF(trusted)))
    {
        return ControllerNodePinTrustedOperatorFingerprint(fingerprint);
    }

    return (_stricmp(trusted, fingerprint) == 0);
}

static BOOL ControllerNodeBase64Encode(_In_reads_bytes_(dataLength) const BYTE *data, _In_ DWORD dataLength,
                                       _Out_writes_z_(destinationChars) PSTR destination, _In_ DWORD destinationChars)
{
    DWORD required = destinationChars;

    return CryptBinaryToStringA(data, dataLength, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, destination, &required);
}

static BOOL ControllerNodeBase64Decode(_In_z_ PCSTR input, _Out_writes_bytes_(outputCapacity) PBYTE output,
                                       _In_ DWORD outputCapacity, _Out_ DWORD *bytesDecoded)
{
    DWORD required = outputCapacity;

    if (bytesDecoded != NULL)
    {
        *bytesDecoded = 0;
    }

    if (!CryptStringToBinaryA(input, 0, CRYPT_STRING_BASE64, output, &required, NULL, NULL))
    {
        return FALSE;
    }

    if (bytesDecoded != NULL)
    {
        *bytesDecoded = required;
    }
    return TRUE;
}

static BOOL ControllerNodeJsonExtractString(_In_z_ PCSTR json, _In_z_ PCSTR key, _Out_writes_z_(valueChars) PSTR value,
                                            _In_ size_t valueChars)
{
    CHAR pattern[96];
    PCSTR start;
    PCSTR end;
    size_t length;

    if (json == NULL || key == NULL || value == NULL || valueChars == 0 ||
        FAILED(StringCchPrintfA(pattern, RTL_NUMBER_OF(pattern), "\"%s\":\"", key)))
    {
        return FALSE;
    }

    start = strstr(json, pattern);
    if (start == NULL)
    {
        return FALSE;
    }
    start += strlen(pattern);
    end = strchr(start, '"');
    if (end == NULL)
    {
        return FALSE;
    }

    length = (size_t)(end - start);
    if (length + 1u > valueChars)
    {
        return FALSE;
    }

    CopyMemory(value, start, length);
    value[length] = '\0';
    return TRUE;
}

static BOOL ControllerNodeJsonExtractUint64(_In_z_ PCSTR json, _In_z_ PCSTR key, _Out_ ULONGLONG *value)
{
    CHAR pattern[96];
    PCSTR start;

    if (json == NULL || key == NULL || value == NULL ||
        FAILED(StringCchPrintfA(pattern, RTL_NUMBER_OF(pattern), "\"%s\":", key)))
    {
        return FALSE;
    }

    start = strstr(json, pattern);
    if (start == NULL)
    {
        return FALSE;
    }
    start += strlen(pattern);
    *value = _strtoui64(start, NULL, 10);
    return TRUE;
}

static BOOL ControllerNodeJsonEscapeString(_In_opt_z_ PCSTR source, _Out_writes_z_(destinationChars) PSTR destination,
                                           _In_ size_t destinationChars)
{
    size_t inIndex = 0;
    size_t outIndex = 0;

    if (destination == NULL || destinationChars == 0)
    {
        return FALSE;
    }

    destination[0] = '\0';
    if (source == NULL)
    {
        return TRUE;
    }

    while (source[inIndex] != '\0')
    {
        CHAR ch = source[inIndex++];
        PCSTR replacement = NULL;
        CHAR unicodeEscape[7];
        size_t replacementLength = 0;

        switch (ch)
        {
        case '\\':
            replacement = "\\\\";
            break;
        case '"':
            replacement = "\\\"";
            break;
        case '\r':
            replacement = "\\r";
            break;
        case '\n':
            replacement = "\\n";
            break;
        case '\t':
            replacement = "\\t";
            break;
        default:
            if ((unsigned char)ch < 0x20u)
            {
                (void)StringCchPrintfA(unicodeEscape, RTL_NUMBER_OF(unicodeEscape), "\\u%04x",
                                       (unsigned int)(unsigned char)ch);
                replacement = unicodeEscape;
            }
            break;
        }

        if (replacement != NULL)
        {
            replacementLength = strlen(replacement);
            if (outIndex + replacementLength + 1u > destinationChars)
            {
                return FALSE;
            }

            CopyMemory(destination + outIndex, replacement, replacementLength);
            outIndex += replacementLength;
        }
        else
        {
            if (outIndex + 2u > destinationChars)
            {
                return FALSE;
            }

            destination[outIndex++] = ch;
        }
    }

    destination[outIndex] = '\0';
    return TRUE;
}

static BOOL ControllerNodeCopyWideToAnsi(_In_opt_z_ PCWSTR source, _Out_writes_z_(destinationChars) PSTR destination,
                                         _In_ size_t destinationChars)
{
    int written;

    if (destination == NULL || destinationChars == 0)
    {
        return FALSE;
    }

    destination[0] = '\0';
    if (source == NULL)
    {
        return TRUE;
    }

    written = WideCharToMultiByte(CP_UTF8, 0, source, -1, destination, (int)destinationChars, NULL, NULL);
    return (written > 0);
}

static BOOL ControllerNodeSanitizeToken(_In_z_ PCSTR input, _Out_writes_z_(outputChars) PSTR output,
                                        _In_ size_t outputChars)
{
    size_t inIndex;
    size_t outIndex = 0;

    if (input == NULL || output == NULL || outputChars == 0)
    {
        return FALSE;
    }

    for (inIndex = 0; input[inIndex] != '\0'; ++inIndex)
    {
        CHAR ch = input[inIndex];
        if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-' ||
            ch == '_' || ch == '.')
        {
            if (outIndex + 2u > outputChars)
            {
                return FALSE;
            }

            output[outIndex++] = ch;
        }
    }

    if (outIndex == 0)
    {
        return FALSE;
    }

    output[outIndex] = '\0';
    return TRUE;
}

static BOOL ControllerNodeBuildJobDirectoryPath(_In_z_ PCSTR jobId, _Out_writes_z_(pathChars) PWSTR path,
                                                _In_ size_t pathChars)
{
    CHAR safeJobId[80];
    WCHAR safeJobIdWide[80];
    WCHAR suffix[160];

    if (!ControllerNodeEnsureStorageDirectories() ||
        !ControllerNodeSanitizeToken(jobId, safeJobId, RTL_NUMBER_OF(safeJobId)) ||
        MultiByteToWideChar(CP_UTF8, 0, safeJobId, -1, safeJobIdWide, RTL_NUMBER_OF(safeJobIdWide)) <= 0 ||
        FAILED(StringCchPrintfW(suffix, RTL_NUMBER_OF(suffix), L"jobs\\%s", safeJobIdWide)))
    {
        return FALSE;
    }

    return ControllerNodeBuildProgramDataPath(path, pathChars, suffix);
}

static BOOL ControllerNodeEnsureJobDirectory(_In_z_ PCSTR jobId, _Out_writes_z_(pathChars) PWSTR path,
                                             _In_ size_t pathChars)
{
    if (!ControllerNodeBuildJobDirectoryPath(jobId, path, pathChars))
    {
        return FALSE;
    }

    return ControllerNodeEnsureDirectory(path);
}

static BOOL ControllerNodeBuildJobFilePath(_In_z_ PCSTR jobId, _In_z_ PCWSTR fileName,
                                           _Out_writes_z_(pathChars) PWSTR path, _In_ size_t pathChars)
{
    WCHAR jobDirectory[MAX_PATH];

    if (!ControllerNodeBuildJobDirectoryPath(jobId, jobDirectory, RTL_NUMBER_OF(jobDirectory)))
    {
        return FALSE;
    }

    return SUCCEEDED(StringCchPrintfW(path, pathChars, L"%s\\%s", jobDirectory, fileName));
}

static BOOL ControllerNodeReadEntireFile(_In_z_ PCWSTR path, _Outptr_result_bytebuffer_(*bytesRead) PBYTE *buffer,
                                         _Out_ DWORD *bytesRead)
{
    HANDLE fileHandle = INVALID_HANDLE_VALUE;
    LARGE_INTEGER size;
    PBYTE localBuffer = NULL;
    DWORD read = 0;
    BOOL success = FALSE;

    if (buffer == NULL || bytesRead == NULL)
    {
        return FALSE;
    }

    *buffer = NULL;
    *bytesRead = 0;
    fileHandle = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (fileHandle == INVALID_HANDLE_VALUE)
    {
        return FALSE;
    }

    if (!GetFileSizeEx(fileHandle, &size) || size.QuadPart < 0 || size.QuadPart > BLACKBIRD_NODE_MAX_UPLOAD_BYTES)
    {
        goto Cleanup;
    }

    localBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, (SIZE_T)size.QuadPart + 1u);
    if (localBuffer == NULL)
    {
        goto Cleanup;
    }

    if (!ReadFile(fileHandle, localBuffer, (DWORD)size.QuadPart, &read, NULL) || read != (DWORD)size.QuadPart)
    {
        goto Cleanup;
    }

    *buffer = localBuffer;
    *bytesRead = read;
    localBuffer = NULL;
    success = TRUE;

Cleanup:
    if (localBuffer != NULL)
    {
        HeapFree(GetProcessHeap(), 0, localBuffer);
    }
    if (fileHandle != INVALID_HANDLE_VALUE)
    {
        CloseHandle(fileHandle);
    }

    return success;
}

static BOOL ControllerNodeReadJobDisplayName(_In_z_ PCSTR jobId, _Out_writes_z_(nameChars) PSTR name,
                                             _In_ size_t nameChars)
{
    WCHAR namePath[MAX_PATH];
    BYTE buffer[260];
    DWORD bytesRead = 0;

    if (name == NULL || nameChars == 0 ||
        !ControllerNodeBuildJobFilePath(jobId, L"sample.name.txt", namePath, RTL_NUMBER_OF(namePath)) ||
        !ControllerNodeReadSmallFile(namePath, buffer, sizeof(buffer) - 1u, &bytesRead) || bytesRead == 0)
    {
        return FALSE;
    }

    buffer[bytesRead] = '\0';
    return SUCCEEDED(StringCchCopyA(name, nameChars, (PCSTR)buffer));
}

static BOOL ControllerNodeFormatSha256Hex(_In_reads_bytes_(32) const BYTE *hash, _Out_writes_z_(hexChars) PSTR hex,
                                          _In_ size_t hexChars)
{
    size_t index;

    if (hash == NULL || hex == NULL || hexChars < 65u)
    {
        return FALSE;
    }

    hex[0] = '\0';
    for (index = 0; index < 32u; ++index)
    {
        (void)StringCchPrintfA(hex + (index * 2u), hexChars - (index * 2u), "%02x", hash[index]);
    }

    return TRUE;
}

static BOOL ControllerNodeReceiveLine(_In_ SOCKET socketHandle, _Out_writes_z_(bufferChars) PSTR buffer,
                                      _In_ size_t bufferChars)
{
    size_t index = 0;

    if (buffer == NULL || bufferChars == 0)
    {
        return FALSE;
    }

    buffer[0] = '\0';
    while (index + 1u < bufferChars)
    {
        CHAR ch = '\0';
        int received = recv(socketHandle, &ch, 1, 0);
        if (received <= 0)
        {
            return FALSE;
        }
        if (ch == '\n')
        {
            break;
        }
        if (ch == '\r')
        {
            continue;
        }
        buffer[index++] = ch;
    }

    buffer[index] = '\0';
    return (index != 0);
}

static BOOL ControllerNodeSendLine(_In_ SOCKET socketHandle, _In_z_ PCSTR line)
{
    PCHAR buffer = NULL;
    size_t bufferChars;
    size_t total;
    size_t sent = 0;
    BOOL success = FALSE;

    if (line == NULL)
    {
        return FALSE;
    }

    bufferChars = strlen(line) + 2u;
    buffer = (PCHAR)HeapAlloc(GetProcessHeap(), 0, bufferChars);
    if (buffer == NULL || FAILED(StringCchPrintfA(buffer, bufferChars, "%s\n", line)))
    {
        goto Cleanup;
    }

    total = strlen(buffer);
    while (sent < total)
    {
        int result = send(socketHandle, buffer + sent, (int)(total - sent), 0);
        if (result <= 0)
        {
            goto Cleanup;
        }
        sent += (size_t)result;
    }

    success = TRUE;

Cleanup:
    if (buffer != NULL)
    {
        HeapFree(GetProcessHeap(), 0, buffer);
    }

    return success;
}

static BOOL ControllerNodeSendRaw(_In_ SOCKET socketHandle, _In_reads_bytes_(bytesToSend) const BYTE *buffer,
                                  _In_ DWORD bytesToSend)
{
    DWORD sent = 0;

    while (sent < bytesToSend)
    {
        int result = send(socketHandle, (const CHAR *)buffer + sent, (int)(bytesToSend - sent), 0);
        if (result <= 0)
        {
            return FALSE;
        }
        sent += (DWORD)result;
    }

    return TRUE;
}

static VOID ControllerNodeBuildNonce(_In_ ULONGLONG sequence, _In_ BOOL fromClient,
                                     _Out_writes_bytes_(BLACKBIRD_NODE_NONCE_BYTES) PBYTE nonce)
{
    ZeroMemory(nonce, BLACKBIRD_NODE_NONCE_BYTES);
    nonce[0] = fromClient ? 'C' : 'S';
    nonce[4] = (BYTE)((sequence >> 56) & 0xFFu);
    nonce[5] = (BYTE)((sequence >> 48) & 0xFFu);
    nonce[6] = (BYTE)((sequence >> 40) & 0xFFu);
    nonce[7] = (BYTE)((sequence >> 32) & 0xFFu);
    nonce[8] = (BYTE)((sequence >> 24) & 0xFFu);
    nonce[9] = (BYTE)((sequence >> 16) & 0xFFu);
    nonce[10] = (BYTE)((sequence >> 8) & 0xFFu);
    nonce[11] = (BYTE)(sequence & 0xFFu);
}

static BOOL ControllerNodeSocketSetTimeouts(_In_ SOCKET socketHandle, _In_ DWORD receiveTimeoutMs,
                                            _In_ DWORD sendTimeoutMs)
{
    return (
        setsockopt(socketHandle, SOL_SOCKET, SO_RCVTIMEO, (const CHAR *)&receiveTimeoutMs, sizeof(receiveTimeoutMs)) ==
            0 &&
        setsockopt(socketHandle, SOL_SOCKET, SO_SNDTIMEO, (const CHAR *)&sendTimeoutMs, sizeof(sendTimeoutMs)) == 0);
}

static BOOL ControllerNodeCreateUdpListener(_In_ USHORT port, _Out_ SOCKET *socketHandle)
{
    SOCKET s = INVALID_SOCKET;
    struct sockaddr_in address;
    BOOL yes = TRUE;

    if (socketHandle == NULL)
    {
        return FALSE;
    }

    s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET)
    {
        return FALSE;
    }

    (void)setsockopt(s, SOL_SOCKET, SO_BROADCAST, (const CHAR *)&yes, sizeof(yes));
    (void)setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const CHAR *)&yes, sizeof(yes));

    ZeroMemory(&address, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    address.sin_port = htons(port);
    if (bind(s, (const struct sockaddr *)&address, sizeof(address)) != 0)
    {
        closesocket(s);
        return FALSE;
    }

    *socketHandle = s;
    return TRUE;
}

static BOOL ControllerNodeCreateTcpListener(_In_ USHORT port, _Out_ SOCKET *socketHandle)
{
    SOCKET s = INVALID_SOCKET;
    struct sockaddr_in address;
    BOOL yes = TRUE;

    if (socketHandle == NULL)
    {
        return FALSE;
    }

    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET)
    {
        return FALSE;
    }

    (void)setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (const CHAR *)&yes, sizeof(yes));
    (void)setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const CHAR *)&yes, sizeof(yes));

    ZeroMemory(&address, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    address.sin_port = htons(port);
    if (bind(s, (const struct sockaddr *)&address, sizeof(address)) != 0 || listen(s, SOMAXCONN) != 0)
    {
        closesocket(s);
        return FALSE;
    }

    *socketHandle = s;
    return TRUE;
}

static BOOL ControllerNodeBuildWireMessage(_In_z_ PCSTR kind, _Out_writes_z_(bufferChars) PSTR buffer,
                                           _In_ size_t bufferChars)
{
    CHAR hostName[128];
    CHAR osVersion[64];
    CHAR kernelVersion[64];
    CHAR timestampUtc[64];
    DWORD activeClients;
    BOOL driverConnected;
    BOOL threatIntelEnabled;
    DWORD threatIntelEnableError;

    if (buffer == NULL || bufferChars == 0 || !ControllerNodeEnsureIdentityLoaded())
    {
        return FALSE;
    }

    ControllerNodeGetComputerNameUtf8(hostName, RTL_NUMBER_OF(hostName));
    ControllerNodeGetVersionString(osVersion, RTL_NUMBER_OF(osVersion));
    ControllerNodeGetVersionString(kernelVersion, RTL_NUMBER_OF(kernelVersion));
    ControllerNodeFormatUtcNow(timestampUtc, RTL_NUMBER_OF(timestampUtc));

    EnterCriticalSection(g_ClientListLock.get());
    activeClients = g_ClientCount;
    LeaveCriticalSection(g_ClientListLock.get());

    EnterCriticalSection(g_DriverLock.get());
    driverConnected = (g_DriverHandle != INVALID_HANDLE_VALUE);
    LeaveCriticalSection(g_DriverLock.get());

    threatIntelEnabled = g_ThreatIntelEnabled;
    threatIntelEnableError = g_ThreatIntelEnableError;

    return SUCCEEDED(StringCchPrintfA(
        buffer, bufferChars,
        "{\"kind\":\"%s\",\"protocol\":1,\"nodeId\":\"%s\",\"hostName\":\"%s\",\"displayName\":\"%s\",\"controllerVersion\":\"%s\",\"osVersion\":\"%s\",\"kernelVersion\":\"%s\",\"statusPort\":%u,\"commandPort\":%u,\"identityFingerprint\":\"%s\",\"busy\":%s,\"driverConnected\":%s,\"threatIntelEnabled\":%s,\"threatIntelEnableError\":%lu,\"activeClients\":%lu,\"timestampUtc\":\"%s\"}",
        kind, g_NodeIdentityFingerprint, hostName, hostName, BLACKBIRD_CONTROLLER_VERSIONA, osVersion, kernelVersion,
        (UINT)BLACKBIRD_OPERATOR_STATUS_PORT, (UINT)BLACKBIRD_OPERATOR_COMMAND_PORT, g_NodeIdentityFingerprint,
        activeClients != 0 ? "true" : "false", driverConnected ? "true" : "false",
        threatIntelEnabled ? "true" : "false", threatIntelEnableError, activeClients, timestampUtc));
}

static BOOL ControllerNodeComputeSessionKey(_In_reads_bytes_(secretLength) const BYTE *secretMaterial,
                                            _In_ ULONG secretLength,
                                            _In_reads_bytes_(clientNonceLength) const BYTE *clientNonce,
                                            _In_ ULONG clientNonceLength,
                                            _In_reads_bytes_(serverNonceLength) const BYTE *serverNonce,
                                            _In_ ULONG serverNonceLength,
                                            _Out_writes_bytes_(BLACKBIRD_NODE_SESSION_KEY_BYTES) PBYTE sessionKey)
{
    BYTE material[512];
    size_t labelLength = strlen(BLACKBIRD_NODE_SESSION_LABEL);
    ULONG totalLength;

    if (secretLength + clientNonceLength + serverNonceLength + (ULONG)labelLength > sizeof(material))
    {
        return FALSE;
    }

    totalLength = 0;
    CopyMemory(material + totalLength, secretMaterial, secretLength);
    totalLength += secretLength;
    CopyMemory(material + totalLength, clientNonce, clientNonceLength);
    totalLength += clientNonceLength;
    CopyMemory(material + totalLength, serverNonce, serverNonceLength);
    totalLength += serverNonceLength;
    CopyMemory(material + totalLength, BLACKBIRD_NODE_SESSION_LABEL, labelLength);
    totalLength += (ULONG)labelLength;

    return ControllerNodeComputeSha256(material, totalLength, sessionKey);
}

static BOOL ControllerNodeBuildTranscript(_In_z_ PCSTR operatorFingerprint, _In_z_ PCSTR nodeId,
                                          _In_z_ PCSTR clientNonceBase64, _In_z_ PCSTR serverNonceBase64,
                                          _In_z_ PCSTR clientEcdhPublicBase64, _In_z_ PCSTR serverEcdhPublicBase64,
                                          _Out_writes_bytes_(bufferCapacity) PBYTE buffer, _In_ DWORD bufferCapacity,
                                          _Out_ DWORD *bytesWritten)
{
    int written;

    written = _snprintf_s((char *)buffer, bufferCapacity, _TRUNCATE, "%s\n%s\n%s\n%s\n%s\n%s\n%s",
                          BLACKBIRD_NODE_HANDSHAKE_LABEL, operatorFingerprint, nodeId, clientNonceBase64,
                          serverNonceBase64, clientEcdhPublicBase64, serverEcdhPublicBase64);
    if (written <= 0)
    {
        return FALSE;
    }

    if (bytesWritten != NULL)
    {
        *bytesWritten = (DWORD)written;
    }
    return TRUE;
}

static BOOL ControllerNodeEcdsaSignData(_In_reads_bytes_(privateBlobLength) const BYTE *privateBlob,
                                        _In_ ULONG privateBlobLength, _In_reads_bytes_(dataLength) const BYTE *data,
                                        _In_ ULONG dataLength, _Out_writes_bytes_(signatureCapacity) PBYTE signature,
                                        _In_ ULONG signatureCapacity, _Out_ ULONG *signatureLength)
{
    BCRYPT_ALG_HANDLE algorithm = NULL;
    BCRYPT_KEY_HANDLE keyHandle = NULL;
    BYTE digest[32];
    NTSTATUS status;
    BOOL success = FALSE;

    if (!ControllerNodeComputeSha256(data, dataLength, digest))
    {
        return FALSE;
    }

    status = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_ECDSA_P256_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status))
    {
        return FALSE;
    }

    status = BCryptImportKeyPair(algorithm, NULL, BCRYPT_ECCPRIVATE_BLOB, &keyHandle, (PUCHAR)privateBlob,
                                 privateBlobLength, 0);
    if (!BCRYPT_SUCCESS(status))
    {
        goto Cleanup;
    }

    status = BCryptSignHash(keyHandle, NULL, digest, RTL_NUMBER_OF(digest), signature, signatureCapacity,
                            signatureLength, 0);
    if (!BCRYPT_SUCCESS(status))
    {
        goto Cleanup;
    }

    success = TRUE;

Cleanup:
    if (keyHandle != NULL)
    {
        BCryptDestroyKey(keyHandle);
    }
    if (algorithm != NULL)
    {
        BCryptCloseAlgorithmProvider(algorithm, 0);
    }

    return success;
}

static BOOL ControllerNodeEcdsaVerifyData(_In_reads_bytes_(publicBlobLength) const BYTE *publicBlob,
                                          _In_ ULONG publicBlobLength, _In_reads_bytes_(dataLength) const BYTE *data,
                                          _In_ ULONG dataLength,
                                          _In_reads_bytes_(signatureLength) const BYTE *signature,
                                          _In_ ULONG signatureLength)
{
    BCRYPT_ALG_HANDLE algorithm = NULL;
    BCRYPT_KEY_HANDLE keyHandle = NULL;
    BYTE digest[32];
    NTSTATUS status;
    BOOL success = FALSE;

    if (!ControllerNodeComputeSha256(data, dataLength, digest))
    {
        return FALSE;
    }

    status = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_ECDSA_P256_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status))
    {
        return FALSE;
    }

    status = BCryptImportKeyPair(algorithm, NULL, BCRYPT_ECCPUBLIC_BLOB, &keyHandle, (PUCHAR)publicBlob,
                                 publicBlobLength, 0);
    if (!BCRYPT_SUCCESS(status))
    {
        goto Cleanup;
    }

    status =
        BCryptVerifySignature(keyHandle, NULL, digest, RTL_NUMBER_OF(digest), (PUCHAR)signature, signatureLength, 0);
    success = BCRYPT_SUCCESS(status);

Cleanup:
    if (keyHandle != NULL)
    {
        BCryptDestroyKey(keyHandle);
    }
    if (algorithm != NULL)
    {
        BCryptCloseAlgorithmProvider(algorithm, 0);
    }

    return success;
}

static BOOL ControllerNodeDeriveSecretMaterial(_In_ BCRYPT_KEY_HANDLE localPrivateKey,
                                               _In_reads_bytes_(peerPublicBlobLength) const BYTE *peerPublicBlob,
                                               _In_ ULONG peerPublicBlobLength,
                                               _Out_writes_bytes_(secretCapacity) PBYTE secretMaterial,
                                               _In_ ULONG secretCapacity, _Out_ ULONG *secretLength)
{
    BCRYPT_ALG_HANDLE algorithm = NULL;
    BCRYPT_KEY_HANDLE peerKey = NULL;
    BCRYPT_SECRET_HANDLE secret = NULL;
    BCryptBuffer parameterBuffer;
    BCryptBufferDesc parameterDesc;
    NTSTATUS status;
    BOOL success = FALSE;

    status = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_ECDH_P256_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status))
    {
        return FALSE;
    }

    status = BCryptImportKeyPair(algorithm, NULL, BCRYPT_ECCPUBLIC_BLOB, &peerKey, (PUCHAR)peerPublicBlob,
                                 peerPublicBlobLength, 0);
    if (!BCRYPT_SUCCESS(status))
    {
        goto Cleanup;
    }

    status = BCryptSecretAgreement(localPrivateKey, peerKey, &secret, 0);
    if (!BCRYPT_SUCCESS(status))
    {
        goto Cleanup;
    }

    ZeroMemory(&parameterBuffer, sizeof(parameterBuffer));
    parameterBuffer.BufferType = KDF_HASH_ALGORITHM;
    parameterBuffer.pvBuffer = (PVOID)BCRYPT_SHA256_ALGORITHM;
    parameterBuffer.cbBuffer = (ULONG)((wcslen(BCRYPT_SHA256_ALGORITHM) + 1u) * sizeof(WCHAR));
    ZeroMemory(&parameterDesc, sizeof(parameterDesc));
    parameterDesc.ulVersion = BCRYPTBUFFER_VERSION;
    parameterDesc.cBuffers = 1;
    parameterDesc.pBuffers = &parameterBuffer;

    status = BCryptDeriveKey(secret, BCRYPT_KDF_HASH, &parameterDesc, secretMaterial, secretCapacity, secretLength, 0);
    if (!BCRYPT_SUCCESS(status))
    {
        goto Cleanup;
    }

    success = TRUE;

Cleanup:
    if (secret != NULL)
    {
        BCryptDestroySecret(secret);
    }
    if (peerKey != NULL)
    {
        BCryptDestroyKey(peerKey);
    }
    if (algorithm != NULL)
    {
        BCryptCloseAlgorithmProvider(algorithm, 0);
    }

    return success;
}
static BOOL ControllerNodeAesGcmTransform(_In_reads_bytes_(BLACKBIRD_NODE_SESSION_KEY_BYTES) const BYTE *sessionKey,
                                          _In_reads_bytes_(BLACKBIRD_NODE_NONCE_BYTES) const BYTE *nonce,
                                          _In_reads_bytes_(inputLength) const BYTE *input, _In_ ULONG inputLength,
                                          _Out_writes_bytes_(inputLength) PBYTE output,
                                          _Inout_updates_bytes_(BLACKBIRD_NODE_TAG_BYTES) PBYTE tag, _In_ BOOL encrypt)
{
    BCRYPT_ALG_HANDLE algorithm = NULL;
    BCRYPT_KEY_HANDLE keyHandle = NULL;
    PUCHAR keyObject = NULL;
    DWORD objectLength = 0;
    DWORD bytesCopied = 0;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    NTSTATUS status;
    ULONG resultLength = 0;
    BOOL success = FALSE;

    status = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status))
    {
        return FALSE;
    }

    status = BCryptSetProperty(algorithm, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                               (ULONG)((wcslen(BCRYPT_CHAIN_MODE_GCM) + 1u) * sizeof(WCHAR)), 0);
    if (!BCRYPT_SUCCESS(status))
    {
        goto Cleanup;
    }

    status = BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objectLength, sizeof(objectLength),
                               &bytesCopied, 0);
    if (!BCRYPT_SUCCESS(status) || objectLength == 0)
    {
        goto Cleanup;
    }

    keyObject = (PUCHAR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, objectLength);
    if (keyObject == NULL)
    {
        goto Cleanup;
    }

    status = BCryptGenerateSymmetricKey(algorithm, &keyHandle, keyObject, objectLength, (PUCHAR)sessionKey,
                                        BLACKBIRD_NODE_SESSION_KEY_BYTES, 0);
    if (!BCRYPT_SUCCESS(status))
    {
        goto Cleanup;
    }

    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = (PUCHAR)nonce;
    authInfo.cbNonce = BLACKBIRD_NODE_NONCE_BYTES;
    authInfo.pbTag = tag;
    authInfo.cbTag = BLACKBIRD_NODE_TAG_BYTES;

    if (encrypt)
    {
        status = BCryptEncrypt(keyHandle, (PUCHAR)input, inputLength, &authInfo, NULL, 0, output, inputLength,
                               &resultLength, 0);
    }
    else
    {
        status = BCryptDecrypt(keyHandle, (PUCHAR)input, inputLength, &authInfo, NULL, 0, output, inputLength,
                               &resultLength, 0);
    }

    success = (BCRYPT_SUCCESS(status) && resultLength == inputLength);

Cleanup:
    if (keyHandle != NULL)
    {
        BCryptDestroyKey(keyHandle);
    }
    if (keyObject != NULL)
    {
        HeapFree(GetProcessHeap(), 0, keyObject);
    }
    if (algorithm != NULL)
    {
        BCryptCloseAlgorithmProvider(algorithm, 0);
    }

    return success;
}

static BOOL ControllerNodeEncryptEnvelope(_Inout_ PBLACKBIRD_NODE_SECURE_SESSION session,
                                          _In_reads_bytes_(plaintextLength) const BYTE *plaintext,
                                          _In_ DWORD plaintextLength, _Out_writes_z_(bufferChars) PSTR buffer,
                                          _In_ size_t bufferChars)
{
    BYTE nonce[BLACKBIRD_NODE_NONCE_BYTES];
    BYTE tag[BLACKBIRD_NODE_TAG_BYTES];
    BYTE ciphertext[BLACKBIRD_NODE_MAX_COMMAND_PLAINTEXT];
    CHAR nonceBase64[64];
    CHAR tagBase64[64];
    CHAR ciphertextBase64[65536];

    if (session == NULL || plaintextLength > sizeof(ciphertext))
    {
        return FALSE;
    }

    session->OutboundSequence += 1;
    ControllerNodeBuildNonce(session->OutboundSequence, FALSE, nonce);
    ZeroMemory(tag, sizeof(tag));
    if (!ControllerNodeAesGcmTransform(session->SessionKey, nonce, plaintext, plaintextLength, ciphertext, tag, TRUE) ||
        !ControllerNodeBase64Encode(nonce, sizeof(nonce), nonceBase64, RTL_NUMBER_OF(nonceBase64)) ||
        !ControllerNodeBase64Encode(tag, sizeof(tag), tagBase64, RTL_NUMBER_OF(tagBase64)) ||
        !ControllerNodeBase64Encode(ciphertext, plaintextLength, ciphertextBase64, RTL_NUMBER_OF(ciphertextBase64)))
    {
        return FALSE;
    }

    return SUCCEEDED(StringCchPrintfA(
        buffer, bufferChars, "{\"kind\":\"%s\",\"seq\":%llu,\"nonce\":\"%s\",\"tag\":\"%s\",\"ciphertext\":\"%s\"}",
        BLACKBIRD_NODE_SECURE_KIND, session->OutboundSequence, nonceBase64, tagBase64, ciphertextBase64));
}

static BOOL ControllerNodeDecryptEnvelope(_Inout_ PBLACKBIRD_NODE_SECURE_SESSION session, _In_z_ PCSTR json,
                                          _Out_writes_bytes_(plaintextCapacity) PBYTE plaintext,
                                          _In_ DWORD plaintextCapacity, _Out_ DWORD *plaintextLength)
{
    CHAR nonceBase64[64];
    CHAR tagBase64[64];
    CHAR ciphertextBase64[65536];
    BYTE expectedNonce[BLACKBIRD_NODE_NONCE_BYTES];
    BYTE nonce[BLACKBIRD_NODE_NONCE_BYTES];
    BYTE tag[BLACKBIRD_NODE_TAG_BYTES];
    BYTE ciphertext[BLACKBIRD_NODE_MAX_COMMAND_PLAINTEXT];
    DWORD nonceLength = 0;
    DWORD tagLength = 0;
    DWORD ciphertextLength = 0;
    ULONGLONG sequence = 0;

    if (session == NULL || json == NULL || plaintext == NULL || plaintextLength == NULL ||
        !ControllerNodeJsonExtractUint64(json, "seq", &sequence) ||
        !ControllerNodeJsonExtractString(json, "nonce", nonceBase64, RTL_NUMBER_OF(nonceBase64)) ||
        !ControllerNodeJsonExtractString(json, "tag", tagBase64, RTL_NUMBER_OF(tagBase64)) ||
        !ControllerNodeJsonExtractString(json, "ciphertext", ciphertextBase64, RTL_NUMBER_OF(ciphertextBase64)))
    {
        return FALSE;
    }

    if (sequence != (session->ExpectedInboundSequence + 1u) ||
        !ControllerNodeBase64Decode(nonceBase64, nonce, sizeof(nonce), &nonceLength) || nonceLength != sizeof(nonce) ||
        !ControllerNodeBase64Decode(tagBase64, tag, sizeof(tag), &tagLength) || tagLength != sizeof(tag) ||
        !ControllerNodeBase64Decode(ciphertextBase64, ciphertext, sizeof(ciphertext), &ciphertextLength) ||
        ciphertextLength > plaintextCapacity)
    {
        return FALSE;
    }

    ControllerNodeBuildNonce(sequence, TRUE, expectedNonce);
    if (memcmp(nonce, expectedNonce, sizeof(nonce)) != 0 ||
        !ControllerNodeAesGcmTransform(session->SessionKey, nonce, ciphertext, ciphertextLength, plaintext, tag, FALSE))
    {
        return FALSE;
    }

    session->ExpectedInboundSequence = sequence;
    *plaintextLength = ciphertextLength;
    return TRUE;
}

static BOOL ControllerNodeBuildCommandResponse(_In_ BOOL ok, _In_opt_z_ PCSTR reply, _In_opt_z_ PCSTR error,
                                               _Out_writes_z_(bufferChars) PSTR buffer, _In_ size_t bufferChars)
{
    CHAR escapedReply[512];
    CHAR escapedError[512];

    if (!ControllerNodeJsonEscapeString(reply, escapedReply, RTL_NUMBER_OF(escapedReply)) ||
        !ControllerNodeJsonEscapeString(error, escapedError, RTL_NUMBER_OF(escapedError)))
    {
        return FALSE;
    }

    return SUCCEEDED(StringCchPrintfA(buffer, bufferChars,
                                      "{\"ok\":%s,\"reply\":\"%s\",\"error\":\"%s\",\"payload\":null}",
                                      ok ? "true" : "false", escapedReply, escapedError));
}

static BOOL ControllerNodeBuildCommandResponseWithPayload(_In_ BOOL ok, _In_opt_z_ PCSTR reply, _In_opt_z_ PCSTR error,
                                                          _In_opt_z_ PCSTR payloadJson,
                                                          _Out_writes_z_(bufferChars) PSTR buffer,
                                                          _In_ size_t bufferChars)
{
    CHAR escapedReply[512];
    CHAR escapedError[512];

    if (!ControllerNodeJsonEscapeString(reply, escapedReply, RTL_NUMBER_OF(escapedReply)) ||
        !ControllerNodeJsonEscapeString(error, escapedError, RTL_NUMBER_OF(escapedError)))
    {
        return FALSE;
    }

    return SUCCEEDED(StringCchPrintfA(
        buffer, bufferChars, "{\"ok\":%s,\"reply\":\"%s\",\"error\":\"%s\",\"payload\":%s}", ok ? "true" : "false",
        escapedReply, escapedError, payloadJson != NULL ? payloadJson : "null"));
}

static BOOL ControllerNodeHandleUploadStart(_In_z_ PCSTR plaintext, _Out_writes_z_(responseChars) PSTR responseJson,
                                            _In_ size_t responseChars)
{
    CHAR jobId[80];
    CHAR fileName[260];
    CHAR safeFileName[260];
    WCHAR jobDirectory[MAX_PATH];
    WCHAR samplePath[MAX_PATH];
    WCHAR namePath[MAX_PATH];
    ULONGLONG totalBytes = 0;
    CHAR escapedName[320];
    CHAR payloadJson[512];

    if (!ControllerNodeJsonExtractString(plaintext, "jobId", jobId, RTL_NUMBER_OF(jobId)) ||
        !ControllerNodeJsonExtractString(plaintext, "fileName", fileName, RTL_NUMBER_OF(fileName)) ||
        !ControllerNodeJsonExtractUint64(plaintext, "totalBytes", &totalBytes) || totalBytes == 0 ||
        totalBytes > BLACKBIRD_NODE_MAX_UPLOAD_BYTES ||
        !ControllerNodeSanitizeToken(fileName, safeFileName, RTL_NUMBER_OF(safeFileName)) ||
        !ControllerNodeEnsureJobDirectory(jobId, jobDirectory, RTL_NUMBER_OF(jobDirectory)) ||
        !ControllerNodeBuildJobFilePath(jobId, L"sample.bin", samplePath, RTL_NUMBER_OF(samplePath)) ||
        !ControllerNodeBuildJobFilePath(jobId, L"sample.name.txt", namePath, RTL_NUMBER_OF(namePath)) ||
        !ControllerNodeWriteSmallFile(samplePath, (const BYTE *)"", 0) ||
        !ControllerNodeWriteSmallFile(namePath, (const BYTE *)safeFileName, (DWORD)strlen(safeFileName)) ||
        !ControllerNodeJsonEscapeString(safeFileName, escapedName, RTL_NUMBER_OF(escapedName)) ||
        FAILED(StringCchPrintfA(payloadJson, RTL_NUMBER_OF(payloadJson),
                                "{\"jobId\":\"%s\",\"fileName\":\"%s\",\"totalBytes\":%llu}", jobId, escapedName,
                                totalBytes)))
    {
        return ControllerNodeBuildCommandResponse(FALSE, "", "Upload start payload was invalid.", responseJson,
                                                  responseChars);
    }

    return ControllerNodeBuildCommandResponseWithPayload(TRUE, "UPLOAD_READY", "", payloadJson, responseJson,
                                                         responseChars);
}

static BOOL ControllerNodeHandleUploadChunk(_In_z_ PCSTR plaintext, _Out_writes_z_(responseChars) PSTR responseJson,
                                            _In_ size_t responseChars)
{
    CHAR jobId[80];
    CHAR chunkBase64[32768];
    WCHAR samplePath[MAX_PATH];
    BYTE chunkBytes[BLACKBIRD_NODE_UPLOAD_CHUNK_BYTES];
    DWORD decoded = 0;
    ULONGLONG chunkIndex = 0;
    LARGE_INTEGER size;
    HANDLE fileHandle = INVALID_HANDLE_VALUE;
    CHAR payloadJson[256];
    BOOL ok = FALSE;

    if (!ControllerNodeJsonExtractString(plaintext, "jobId", jobId, RTL_NUMBER_OF(jobId)) ||
        !ControllerNodeJsonExtractString(plaintext, "chunkBase64", chunkBase64, RTL_NUMBER_OF(chunkBase64)) ||
        !ControllerNodeJsonExtractUint64(plaintext, "chunkIndex", &chunkIndex) ||
        !ControllerNodeBuildJobFilePath(jobId, L"sample.bin", samplePath, RTL_NUMBER_OF(samplePath)) ||
        !ControllerNodeBase64Decode(chunkBase64, chunkBytes, sizeof(chunkBytes), &decoded) || decoded == 0 ||
        !ControllerNodeAppendFile(samplePath, chunkBytes, decoded))
    {
        return ControllerNodeBuildCommandResponse(FALSE, "", "Upload chunk payload was invalid.", responseJson,
                                                  responseChars);
    }

    fileHandle = CreateFileW(samplePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
                             FILE_ATTRIBUTE_NORMAL, NULL);
    ok =
        (fileHandle != INVALID_HANDLE_VALUE && GetFileSizeEx(fileHandle, &size) &&
         size.QuadPart <= BLACKBIRD_NODE_MAX_UPLOAD_BYTES &&
         SUCCEEDED(StringCchPrintfA(payloadJson, RTL_NUMBER_OF(payloadJson),
                                    "{\"jobId\":\"%s\",\"chunkIndex\":%llu,\"receivedBytes\":%lu,\"storedBytes\":%llu}",
                                    jobId, chunkIndex, (unsigned long)decoded, size.QuadPart)));
    if (fileHandle != INVALID_HANDLE_VALUE)
    {
        CloseHandle(fileHandle);
    }

    if (!ok)
    {
        return ControllerNodeBuildCommandResponse(FALSE, "", "Upload chunk could not be persisted.", responseJson,
                                                  responseChars);
    }

    return ControllerNodeBuildCommandResponseWithPayload(TRUE, "UPLOAD_CHUNK_OK", "", payloadJson, responseJson,
                                                         responseChars);
}

static BOOL ControllerNodeHandleAnalyzeFile(_In_z_ PCSTR plaintext, _Out_writes_z_(responseChars) PSTR responseJson,
                                            _In_ size_t responseChars)
{
    CHAR jobId[80];
    WCHAR samplePath[MAX_PATH];
    WCHAR analysisPath[MAX_PATH];
    CHAR displayName[260];
    PBYTE fileBytes = NULL;
    DWORD fileBytesLength = 0;
    BYTE hash[32];
    CHAR sha256Hex[65];
    CHAR timestampUtc[64];
    CHAR escapedDisplayName[320];
    CHAR samplePathUtf8[512];
    CHAR escapedSamplePath[768];
    CHAR analysisJson[2048];
    CHAR payloadJson[512];
    BOOL success = FALSE;

    if (!ControllerNodeJsonExtractString(plaintext, "jobId", jobId, RTL_NUMBER_OF(jobId)) ||
        !ControllerNodeBuildJobFilePath(jobId, L"sample.bin", samplePath, RTL_NUMBER_OF(samplePath)) ||
        !ControllerNodeBuildJobFilePath(jobId, L"analysis.json", analysisPath, RTL_NUMBER_OF(analysisPath)) ||
        !ControllerNodeReadJobDisplayName(jobId, displayName, RTL_NUMBER_OF(displayName)) ||
        !ControllerNodeReadEntireFile(samplePath, &fileBytes, &fileBytesLength) ||
        !ControllerNodeComputeSha256(fileBytes, fileBytesLength, hash) ||
        !ControllerNodeFormatSha256Hex(hash, sha256Hex, RTL_NUMBER_OF(sha256Hex)) ||
        !ControllerNodeCopyWideToAnsi(samplePath, samplePathUtf8, RTL_NUMBER_OF(samplePathUtf8)) ||
        !ControllerNodeJsonEscapeString(displayName, escapedDisplayName, RTL_NUMBER_OF(escapedDisplayName)) ||
        !ControllerNodeJsonEscapeString(samplePathUtf8, escapedSamplePath, RTL_NUMBER_OF(escapedSamplePath)))
    {
        goto Cleanup;
    }

    ControllerNodeFormatUtcNow(timestampUtc, RTL_NUMBER_OF(timestampUtc));
    success =
        SUCCEEDED(StringCchPrintfA(
            analysisJson, RTL_NUMBER_OF(analysisJson),
            "{"
            "\"schema\":\"blackbird.operator.analysis.v1\","
            "\"jobId\":\"%s\","
            "\"nodeId\":\"%s\","
            "\"controllerVersion\":\"%s\","
            "\"timestampUtc\":\"%s\","
            "\"sample\":{"
            "\"fileName\":\"%s\","
            "\"path\":\"%s\","
            "\"size\":%lu,"
            "\"sha256\":\"%s\""
            "},"
            "\"blackbird\":{"
            "\"analysisMode\":\"node-local-file-triage\","
            "\"driverConnected\":%s,"
            "\"threatIntelEnabled\":%s"
            "},"
            "\"nextStage\":{"
            "\"recommendedHostAction\":\"send this JSON artifact into SVR on the operator host\","
            "\"artifactFileName\":\"analysis.json\""
            "}"
            "}",
            jobId, g_NodeIdentityFingerprint, BLACKBIRD_CONTROLLER_VERSIONA, timestampUtc, escapedDisplayName,
            escapedSamplePath, (unsigned long)fileBytesLength, sha256Hex,
            g_DriverHandle != INVALID_HANDLE_VALUE ? "true" : "false", g_ThreatIntelEnabled ? "true" : "false")) &&
        ControllerNodeWriteSmallFile(analysisPath, (const BYTE *)analysisJson, (DWORD)strlen(analysisJson)) &&
        SUCCEEDED(StringCchPrintfA(payloadJson, RTL_NUMBER_OF(payloadJson),
                                   "{\"jobId\":\"%s\",\"artifact\":\"analysis.json\",\"size\":%u}", jobId,
                                   (unsigned int)strlen(analysisJson)));

Cleanup:
    if (fileBytes != NULL)
    {
        HeapFree(GetProcessHeap(), 0, fileBytes);
    }

    if (!success)
    {
        return ControllerNodeBuildCommandResponse(FALSE, "", "Node analysis generation failed.", responseJson,
                                                  responseChars);
    }

    return ControllerNodeBuildCommandResponseWithPayload(TRUE, "ANALYSIS_READY", "", payloadJson, responseJson,
                                                         responseChars);
}

static BOOL ControllerNodeHandleDownloadFile(_In_z_ PCSTR plaintext, _Out_writes_z_(responseChars) PSTR responseJson,
                                             _In_ size_t responseChars)
{
    CHAR jobId[80];
    CHAR artifactName[80];
    WCHAR filePath[MAX_PATH];
    PBYTE fileBytes = NULL;
    DWORD fileBytesLength = 0;
    CHAR fileBase64[32768];
    CHAR payloadJson[36864];
    BOOL success = FALSE;

    if (!ControllerNodeJsonExtractString(plaintext, "jobId", jobId, RTL_NUMBER_OF(jobId)) ||
        !ControllerNodeJsonExtractString(plaintext, "artifact", artifactName, RTL_NUMBER_OF(artifactName)))
    {
        return ControllerNodeBuildCommandResponse(FALSE, "", "Download payload was invalid.", responseJson,
                                                  responseChars);
    }

    if (_stricmp(artifactName, "analysis.json") != 0 ||
        !ControllerNodeBuildJobFilePath(jobId, L"analysis.json", filePath, RTL_NUMBER_OF(filePath)) ||
        !ControllerNodeReadEntireFile(filePath, &fileBytes, &fileBytesLength) ||
        !ControllerNodeBase64Encode(fileBytes, fileBytesLength, fileBase64, RTL_NUMBER_OF(fileBase64)) ||
        FAILED(StringCchPrintfA(payloadJson, RTL_NUMBER_OF(payloadJson),
                                "{\"jobId\":\"%s\",\"artifact\":\"analysis.json\",\"fileBase64\":\"%s\",\"size\":%lu}",
                                jobId, fileBase64, (unsigned long)fileBytesLength)))
    {
        if (fileBytes != NULL)
        {
            HeapFree(GetProcessHeap(), 0, fileBytes);
        }

        return ControllerNodeBuildCommandResponse(FALSE, "", "Requested artifact was unavailable.", responseJson,
                                                  responseChars);
    }

    success = TRUE;
    HeapFree(GetProcessHeap(), 0, fileBytes);
    return ControllerNodeBuildCommandResponseWithPayload(TRUE, "DOWNLOAD_READY", "", payloadJson, responseJson,
                                                         responseChars);
}

static BOOL ControllerNodeHandleSecureCommand(_Inout_ PBLACKBIRD_NODE_SECURE_SESSION session, _In_ SOCKET clientSocket)
{
    PCHAR line = NULL;
    PBYTE plaintext = NULL;
    DWORD plaintextLength = 0;
    CHAR command[64];
    PCHAR responseJson = NULL;
    PCHAR envelopeJson = NULL;
    BOOL keepRunning = TRUE;

    line = (PCHAR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, BLACKBIRD_NODE_MAX_ENVELOPE_JSON);
    plaintext = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, BLACKBIRD_NODE_MAX_COMMAND_PLAINTEXT + 1u);
    responseJson = (PCHAR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, BLACKBIRD_NODE_MAX_COMMAND_PLAINTEXT + 1u);
    envelopeJson = (PCHAR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, BLACKBIRD_NODE_MAX_ENVELOPE_JSON);
    if (line == NULL || plaintext == NULL || responseJson == NULL || envelopeJson == NULL)
    {
        keepRunning = FALSE;
        goto Cleanup;
    }

    while (ControllerNodeReceiveLine(clientSocket, line, BLACKBIRD_NODE_MAX_ENVELOPE_JSON))
    {
        if (!ControllerNodeDecryptEnvelope(session, line, plaintext, BLACKBIRD_NODE_MAX_COMMAND_PLAINTEXT,
                                           &plaintextLength))
        {
            keepRunning = FALSE;
            break;
        }

        plaintext[plaintextLength] = '\0';
        if (!ControllerNodeJsonExtractString((const CHAR *)plaintext, "command", command, RTL_NUMBER_OF(command)))
        {
            keepRunning = FALSE;
            break;
        }

        if (_stricmp(command, "PING") == 0)
        {
            if (!ControllerNodeBuildCommandResponse(TRUE, "PONG", "", responseJson,
                                                    BLACKBIRD_NODE_MAX_COMMAND_PLAINTEXT))
            {
                keepRunning = FALSE;
                break;
            }
        }
        else if (_stricmp(command, "STATUS") == 0)
        {
            CHAR statusJson[2048];
            if (ControllerNodeBuildWireMessage("blackbird.node.beacon", statusJson, RTL_NUMBER_OF(statusJson)))
            {
                if (!ControllerNodeBuildCommandResponseWithPayload(TRUE, "STATUS_OK", "", statusJson, responseJson,
                                                                   BLACKBIRD_NODE_MAX_COMMAND_PLAINTEXT))
                {
                    keepRunning = FALSE;
                    break;
                }
            }
            else
            {
                if (!ControllerNodeBuildCommandResponse(FALSE, "", "Failed to build status payload.", responseJson,
                                                        BLACKBIRD_NODE_MAX_COMMAND_PLAINTEXT))
                {
                    keepRunning = FALSE;
                    break;
                }
            }
        }
        else if (_stricmp(command, "UPLOAD_FILE_START") == 0)
        {
            if (!ControllerNodeHandleUploadStart((const CHAR *)plaintext, responseJson,
                                                 BLACKBIRD_NODE_MAX_COMMAND_PLAINTEXT))
            {
                keepRunning = FALSE;
                break;
            }
        }
        else if (_stricmp(command, "UPLOAD_FILE_CHUNK") == 0)
        {
            if (!ControllerNodeHandleUploadChunk((const CHAR *)plaintext, responseJson,
                                                 BLACKBIRD_NODE_MAX_COMMAND_PLAINTEXT))
            {
                keepRunning = FALSE;
                break;
            }
        }
        else if (_stricmp(command, "ANALYZE_UPLOADED_FILE") == 0)
        {
            if (!ControllerNodeHandleAnalyzeFile((const CHAR *)plaintext, responseJson,
                                                 BLACKBIRD_NODE_MAX_COMMAND_PLAINTEXT))
            {
                keepRunning = FALSE;
                break;
            }
        }
        else if (_stricmp(command, "DOWNLOAD_FILE") == 0)
        {
            if (!ControllerNodeHandleDownloadFile((const CHAR *)plaintext, responseJson,
                                                  BLACKBIRD_NODE_MAX_COMMAND_PLAINTEXT))
            {
                keepRunning = FALSE;
                break;
            }
        }
        else
        {
            if (!ControllerNodeBuildCommandResponse(FALSE, "", "Unsupported secure node command.", responseJson,
                                                    BLACKBIRD_NODE_MAX_COMMAND_PLAINTEXT))
            {
                keepRunning = FALSE;
                break;
            }
        }

        if (!ControllerNodeEncryptEnvelope(session, (const BYTE *)responseJson, (DWORD)strlen(responseJson),
                                           envelopeJson, BLACKBIRD_NODE_MAX_ENVELOPE_JSON) ||
            !ControllerNodeSendLine(clientSocket, envelopeJson))
        {
            keepRunning = FALSE;
            break;
        }
    }

Cleanup:
    if (line != NULL)
    {
        HeapFree(GetProcessHeap(), 0, line);
    }
    if (plaintext != NULL)
    {
        HeapFree(GetProcessHeap(), 0, plaintext);
    }
    if (responseJson != NULL)
    {
        HeapFree(GetProcessHeap(), 0, responseJson);
    }
    if (envelopeJson != NULL)
    {
        HeapFree(GetProcessHeap(), 0, envelopeJson);
    }

    return keepRunning;
}

static BOOL ControllerNodeHandleCommandClient(_In_ SOCKET clientSocket)
{
    CHAR line[4096];
    CHAR kind[64];
    CHAR operatorFingerprint[BLACKBIRD_NODE_FINGERPRINT_CHARS];
    CHAR clientNonceBase64[128];
    CHAR clientEcdhPublicBase64[256];
    CHAR operatorIdentityPublicBase64[256];
    BYTE operatorIdentityPublic[BLACKBIRD_NODE_IDENTITY_PUBLIC_BLOB_CAPACITY];
    BYTE clientNonce[64];
    BYTE clientEcdhPublic[BLACKBIRD_NODE_IDENTITY_PUBLIC_BLOB_CAPACITY];
    DWORD operatorIdentityPublicLength = 0;
    DWORD clientNonceLength = 0;
    DWORD clientEcdhPublicLength = 0;
    BYTE serverNonce[32];
    CHAR serverNonceBase64[128];
    BCRYPT_ALG_HANDLE ecdhAlgorithm = NULL;
    BCRYPT_KEY_HANDLE ecdhKeyHandle = NULL;
    BYTE serverEcdhPublic[BLACKBIRD_NODE_IDENTITY_PUBLIC_BLOB_CAPACITY];
    ULONG serverEcdhPublicLength = 0;
    CHAR serverEcdhPublicBase64[256];
    BYTE transcript[1024];
    DWORD transcriptLength = 0;
    BYTE serverSignature[128];
    ULONG serverSignatureLength = 0;
    CHAR serverSignatureBase64[256];
    CHAR serverHello[2048];
    CHAR authKind[64];
    CHAR authFingerprint[BLACKBIRD_NODE_FINGERPRINT_CHARS];
    CHAR authSignatureBase64[256];
    BYTE authSignature[128];
    DWORD authSignatureLength = 0;
    BYTE secretMaterial[64];
    ULONG secretLength = 0;
    BLACKBIRD_NODE_SECURE_SESSION session;
    BOOL success = FALSE;

    ZeroMemory(&session, sizeof(session));
    if (!ControllerNodeSocketSetTimeouts(clientSocket, BLACKBIRD_NODE_COMMAND_RECV_TIMEOUT_MS,
                                         BLACKBIRD_NODE_COMMAND_SEND_TIMEOUT_MS) ||
        !ControllerNodeEnsureIdentityLoaded() || !ControllerNodeReceiveLine(clientSocket, line, RTL_NUMBER_OF(line)) ||
        !ControllerNodeJsonExtractString(line, "kind", kind, RTL_NUMBER_OF(kind)) ||
        _stricmp(kind, BLACKBIRD_NODE_CLIENT_HELLO_KIND) != 0 ||
        !ControllerNodeJsonExtractString(line, "operatorFingerprint", operatorFingerprint,
                                         RTL_NUMBER_OF(operatorFingerprint)) ||
        !ControllerNodeJsonExtractString(line, "operatorIdentityPublic", operatorIdentityPublicBase64,
                                         RTL_NUMBER_OF(operatorIdentityPublicBase64)) ||
        !ControllerNodeJsonExtractString(line, "clientNonce", clientNonceBase64, RTL_NUMBER_OF(clientNonceBase64)) ||
        !ControllerNodeJsonExtractString(line, "clientEcdhPublic", clientEcdhPublicBase64,
                                         RTL_NUMBER_OF(clientEcdhPublicBase64)) ||
        !ControllerNodeBase64Decode(operatorIdentityPublicBase64, operatorIdentityPublic,
                                    sizeof(operatorIdentityPublic), &operatorIdentityPublicLength) ||
        !ControllerNodeBase64Decode(clientNonceBase64, clientNonce, sizeof(clientNonce), &clientNonceLength) ||
        !ControllerNodeBase64Decode(clientEcdhPublicBase64, clientEcdhPublic, sizeof(clientEcdhPublic),
                                    &clientEcdhPublicLength))
    {
        return FALSE;
    }

    {
        CHAR computedFingerprint[BLACKBIRD_NODE_FINGERPRINT_CHARS];
        if (!ControllerNodeComputeFingerprint(operatorIdentityPublic, operatorIdentityPublicLength, computedFingerprint,
                                              RTL_NUMBER_OF(computedFingerprint)) ||
            _stricmp(computedFingerprint, operatorFingerprint) != 0 ||
            !BCRYPT_SUCCESS(BCryptGenRandom(NULL, serverNonce, sizeof(serverNonce), BCRYPT_USE_SYSTEM_PREFERRED_RNG)) ||
            !ControllerNodeBase64Encode(serverNonce, sizeof(serverNonce), serverNonceBase64,
                                        RTL_NUMBER_OF(serverNonceBase64)))
        {
            return FALSE;
        }
    }

    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&ecdhAlgorithm, BCRYPT_ECDH_P256_ALGORITHM, NULL, 0)) ||
        !BCRYPT_SUCCESS(BCryptGenerateKeyPair(ecdhAlgorithm, &ecdhKeyHandle, 256u, 0)) ||
        !BCRYPT_SUCCESS(BCryptFinalizeKeyPair(ecdhKeyHandle, 0)) ||
        !BCRYPT_SUCCESS(BCryptExportKey(ecdhKeyHandle, NULL, BCRYPT_ECCPUBLIC_BLOB, serverEcdhPublic,
                                        sizeof(serverEcdhPublic), &serverEcdhPublicLength, 0)) ||
        !ControllerNodeBase64Encode(serverEcdhPublic, serverEcdhPublicLength, serverEcdhPublicBase64,
                                    RTL_NUMBER_OF(serverEcdhPublicBase64)) ||
        !ControllerNodeBuildTranscript(operatorFingerprint, g_NodeIdentityFingerprint, clientNonceBase64,
                                       serverNonceBase64, clientEcdhPublicBase64, serverEcdhPublicBase64, transcript,
                                       sizeof(transcript), &transcriptLength) ||
        !ControllerNodeEcdsaSignData(g_NodeIdentityPrivateBlob, g_NodeIdentityPrivateBlobLength, transcript,
                                     transcriptLength, serverSignature, sizeof(serverSignature),
                                     &serverSignatureLength) ||
        !ControllerNodeBase64Encode(serverSignature, serverSignatureLength, serverSignatureBase64,
                                    RTL_NUMBER_OF(serverSignatureBase64)))
    {
        goto Cleanup;
    }

    {
        CHAR nodeIdentityPublicBase64[256];
        if (!ControllerNodeBase64Encode(g_NodeIdentityPublicBlob, g_NodeIdentityPublicBlobLength,
                                        nodeIdentityPublicBase64, RTL_NUMBER_OF(nodeIdentityPublicBase64)) ||
            FAILED(StringCchPrintfA(
                serverHello, RTL_NUMBER_OF(serverHello),
                "{\"kind\":\"%s\",\"protocol\":1,\"nodeId\":\"%s\",\"identityFingerprint\":\"%s\",\"identityPublic\":\"%s\",\"serverNonce\":\"%s\",\"serverEcdhPublic\":\"%s\",\"signature\":\"%s\"}",
                BLACKBIRD_NODE_SERVER_HELLO_KIND, g_NodeIdentityFingerprint, g_NodeIdentityFingerprint,
                nodeIdentityPublicBase64, serverNonceBase64, serverEcdhPublicBase64, serverSignatureBase64)) ||
            !ControllerNodeSendLine(clientSocket, serverHello) ||
            !ControllerNodeReceiveLine(clientSocket, line, RTL_NUMBER_OF(line)) ||
            !ControllerNodeJsonExtractString(line, "kind", authKind, RTL_NUMBER_OF(authKind)) ||
            _stricmp(authKind, BLACKBIRD_NODE_CLIENT_AUTH_KIND) != 0 ||
            !ControllerNodeJsonExtractString(line, "operatorFingerprint", authFingerprint,
                                             RTL_NUMBER_OF(authFingerprint)) ||
            _stricmp(authFingerprint, operatorFingerprint) != 0 ||
            !ControllerNodeJsonExtractString(line, "signature", authSignatureBase64,
                                             RTL_NUMBER_OF(authSignatureBase64)) ||
            !ControllerNodeBase64Decode(authSignatureBase64, authSignature, sizeof(authSignature),
                                        &authSignatureLength) ||
            !ControllerNodeEcdsaVerifyData(operatorIdentityPublic, operatorIdentityPublicLength, transcript,
                                           transcriptLength, authSignature, authSignatureLength) ||
            !ControllerNodeEnsureTrustedOperator(operatorFingerprint) ||
            !ControllerNodeDeriveSecretMaterial(ecdhKeyHandle, clientEcdhPublic, clientEcdhPublicLength, secretMaterial,
                                                sizeof(secretMaterial), &secretLength) ||
            !ControllerNodeComputeSessionKey(secretMaterial, secretLength, clientNonce, clientNonceLength, serverNonce,
                                             sizeof(serverNonce), session.SessionKey))
        {
            goto Cleanup;
        }
    }

    success = ControllerNodeHandleSecureCommand(&session, clientSocket);

Cleanup:
    if (ecdhKeyHandle != NULL)
    {
        BCryptDestroyKey(ecdhKeyHandle);
    }
    if (ecdhAlgorithm != NULL)
    {
        BCryptCloseAlgorithmProvider(ecdhAlgorithm, 0);
    }

    return success;
}

static DWORD WINAPI ControllerNodeBeaconThreadProc(_In_ LPVOID Context)
{
    SOCKET socketHandle = (SOCKET)Context;
    ULONGLONG lastBeaconTick = 0;

    while (!ControllerShouldStop())
    {
        fd_set readSet;
        struct timeval timeout;
        struct sockaddr_in remoteAddress;
        int remoteLength = sizeof(remoteAddress);
        CHAR query[256];
        CHAR beacon[1536];

        FD_ZERO(&readSet);
        FD_SET(socketHandle, &readSet);
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        if (select(0, &readSet, NULL, NULL, &timeout) > 0 && FD_ISSET(socketHandle, &readSet))
        {
            int received =
                recvfrom(socketHandle, query, sizeof(query) - 1, 0, (struct sockaddr *)&remoteAddress, &remoteLength);
            if (received > 0)
            {
                query[received] = '\0';
                if (ControllerNodeIsPrivateIpv4(&remoteAddress) &&
                    strstr(query, BLACKBIRD_OPERATOR_DISCOVERY_QUERY) != NULL &&
                    ControllerNodeBuildWireMessage(BLACKBIRD_OPERATOR_BEACON_KIND, beacon, RTL_NUMBER_OF(beacon)))
                {
                    (void)sendto(socketHandle, beacon, (int)strlen(beacon), 0, (const struct sockaddr *)&remoteAddress,
                                 sizeof(remoteAddress));
                }
            }
        }

        if (GetTickCount64() - lastBeaconTick >= 2500u &&
            ControllerNodeBuildWireMessage(BLACKBIRD_OPERATOR_BEACON_KIND, beacon, RTL_NUMBER_OF(beacon)))
        {
            struct sockaddr_in broadcastAddress;
            ZeroMemory(&broadcastAddress, sizeof(broadcastAddress));
            broadcastAddress.sin_family = AF_INET;
            broadcastAddress.sin_addr.s_addr = htonl(INADDR_BROADCAST);
            broadcastAddress.sin_port = htons(BLACKBIRD_OPERATOR_DISCOVERY_PORT);
            (void)sendto(socketHandle, beacon, (int)strlen(beacon), 0, (const struct sockaddr *)&broadcastAddress,
                         sizeof(broadcastAddress));
            lastBeaconTick = GetTickCount64();
        }
    }

    return 0;
}

static DWORD WINAPI ControllerNodeStatusThreadProc(_In_ LPVOID Context)
{
    SOCKET listener = (SOCKET)Context;

    while (!ControllerShouldStop())
    {
        struct sockaddr_in remoteAddress;
        int remoteLength = sizeof(remoteAddress);
        SOCKET clientSocket = accept(listener, (struct sockaddr *)&remoteAddress, &remoteLength);
        if (clientSocket == INVALID_SOCKET)
        {
            if (ControllerShouldStop())
            {
                break;
            }
            continue;
        }

        if (!ControllerNodeIsPrivateIpv4(&remoteAddress))
        {
            closesocket(clientSocket);
            continue;
        }

        if (ControllerNodeSocketSetTimeouts(clientSocket, 1500u, 1500u))
        {
            CHAR line[256];
            CHAR statusJson[1536];
            if (ControllerNodeReceiveLine(clientSocket, line, RTL_NUMBER_OF(line)) &&
                strcmp(line, g_NodeStatusQuery) == 0 &&
                ControllerNodeBuildWireMessage(BLACKBIRD_OPERATOR_STATUS_KIND, statusJson, RTL_NUMBER_OF(statusJson)))
            {
                (void)ControllerNodeSendRaw(clientSocket, (const BYTE *)statusJson, (DWORD)strlen(statusJson));
            }
        }

        shutdown(clientSocket, SD_BOTH);
        closesocket(clientSocket);
    }

    return 0;
}

static DWORD WINAPI ControllerNodeCommandThreadProc(_In_ LPVOID Context)
{
    SOCKET listener = (SOCKET)Context;

    while (!ControllerShouldStop())
    {
        struct sockaddr_in remoteAddress;
        int remoteLength = sizeof(remoteAddress);
        SOCKET clientSocket = accept(listener, (struct sockaddr *)&remoteAddress, &remoteLength);
        if (clientSocket == INVALID_SOCKET)
        {
            if (ControllerShouldStop())
            {
                break;
            }
            continue;
        }

        if (!ControllerNodeIsPrivateIpv4(&remoteAddress))
        {
            closesocket(clientSocket);
            continue;
        }

        (void)ControllerNodeHandleCommandClient(clientSocket);
        shutdown(clientSocket, SD_BOTH);
        closesocket(clientSocket);
    }

    return 0;
}

BOOL ControllerNodeNetworkStart(VOID)
{
    WSADATA wsaData;

    if (InterlockedCompareExchange(&g_NodeNetworkStarted, 1, 0) != 0)
    {
        return TRUE;
    }

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0 || !ControllerNodeEnsureIdentityLoaded() ||
        !ControllerNodeCreateUdpListener((USHORT)BLACKBIRD_OPERATOR_DISCOVERY_PORT, &g_NodeBeaconSocket) ||
        !ControllerNodeCreateTcpListener((USHORT)BLACKBIRD_OPERATOR_STATUS_PORT, &g_NodeStatusSocket) ||
        !ControllerNodeCreateTcpListener((USHORT)BLACKBIRD_OPERATOR_COMMAND_PORT, &g_NodeCommandSocket))
    {
        ControllerNodeNetworkStop();
        return FALSE;
    }

    g_NodeBeaconThread = CreateThread(NULL, 0, ControllerNodeBeaconThreadProc, (LPVOID)g_NodeBeaconSocket, 0, NULL);
    g_NodeStatusThread = CreateThread(NULL, 0, ControllerNodeStatusThreadProc, (LPVOID)g_NodeStatusSocket, 0, NULL);
    g_NodeCommandThread = CreateThread(NULL, 0, ControllerNodeCommandThreadProc, (LPVOID)g_NodeCommandSocket, 0, NULL);
    if (g_NodeBeaconThread == NULL || g_NodeStatusThread == NULL || g_NodeCommandThread == NULL)
    {
        ControllerNodeNetworkStop();
        return FALSE;
    }

    ControllerLog("[NODE] discovery/status/command online udp=%u tcp=%u secure=%u fingerprint=%s\n",
                  (UINT)BLACKBIRD_OPERATOR_DISCOVERY_PORT, (UINT)BLACKBIRD_OPERATOR_STATUS_PORT,
                  (UINT)BLACKBIRD_OPERATOR_COMMAND_PORT, g_NodeIdentityFingerprint);
    return TRUE;
}

VOID ControllerNodeNetworkStop(VOID)
{
    HANDLE threads[3];
    DWORD index;

    if (InterlockedExchange(&g_NodeNetworkStarted, 0) == 0)
    {
        return;
    }

    ControllerNodeCloseSocket(&g_NodeBeaconSocket);
    ControllerNodeCloseSocket(&g_NodeStatusSocket);
    ControllerNodeCloseSocket(&g_NodeCommandSocket);

    threads[0] = g_NodeBeaconThread;
    threads[1] = g_NodeStatusThread;
    threads[2] = g_NodeCommandThread;
    g_NodeBeaconThread = NULL;
    g_NodeStatusThread = NULL;
    g_NodeCommandThread = NULL;

    for (index = 0; index < RTL_NUMBER_OF(threads); index++)
    {
        if (threads[index] != NULL)
        {
            (void)WaitForSingleObject(threads[index], 3000);
            CloseHandle(threads[index]);
        }
    }

    WSACleanup();
}
