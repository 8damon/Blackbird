param(
    [string]$EnrollmentPath = "",
    [ValidatePattern('^$|^[0-9a-fA-F]{64}$')]
    [string]$ExpectedServerOperatorFingerprint = "",
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$InstallerArgs = @()
)

$ErrorActionPreference = "Stop"

$scriptDir = (Resolve-Path (Split-Path -Parent $MyInvocation.MyCommand.Path)).Path
$repoRoot = $scriptDir
$installer = Join-Path $scriptDir "installer.ps1"

if (Test-Path -LiteralPath $installer -PathType Leaf) {
    $repoRoot = (Resolve-Path (Join-Path $scriptDir "..")).Path
}
else {
    $installer = Join-Path $scriptDir "Scripts\installer.ps1"
}

function Test-HexFingerprint {
    param([string]$Value)
    return -not [string]::IsNullOrWhiteSpace($Value) -and $Value -match '^[0-9a-fA-F]{64}$'
}

function Resolve-EnrollmentPath {
    param([string]$RequestedPath)

    $candidates = @()
    if (-not [string]::IsNullOrWhiteSpace($RequestedPath)) {
        $candidates += $RequestedPath
    }
    $candidates += (Join-Path $scriptDir "blackbird-vm-enrollment.blackbird")
    $candidates += (Join-Path $repoRoot "blackbird-vm-enrollment.blackbird")
    $candidates += (Join-Path $repoRoot "Scripts\blackbird-vm-enrollment.blackbird")
    $candidates += (Join-Path $scriptDir "enroll.json")
    $candidates += (Join-Path $repoRoot "enroll.json")
    $candidates += (Join-Path $repoRoot "Scripts\enroll.json")

    foreach ($candidate in $candidates) {
        $pathToTry = $candidate
        if (-not [System.IO.Path]::IsPathRooted($pathToTry)) {
            $pathToTry = Join-Path $repoRoot $pathToTry
        }

        $resolved = Resolve-Path -LiteralPath $pathToTry -ErrorAction SilentlyContinue
        if ($null -ne $resolved) {
            return $resolved.Path
        }
    }

    $packageCandidates = @()
    $packageCandidates += @(Get-ChildItem -LiteralPath $scriptDir -Filter "*.blackbird" -File -ErrorAction SilentlyContinue)
    $packageCandidates += @(Get-ChildItem -LiteralPath $repoRoot -Filter "*.blackbird" -File -ErrorAction SilentlyContinue)
    $scriptsDir = Join-Path $repoRoot "Scripts"
    if (Test-Path -LiteralPath $scriptsDir -PathType Container) {
        $packageCandidates += @(Get-ChildItem -LiteralPath $scriptsDir -Filter "*.blackbird" -File -ErrorAction SilentlyContinue)
    }
    if ($packageCandidates.Count -gt 0) {
        return $packageCandidates[0].FullName
    }

    throw "No Blackbird VM enrollment package was found. Copy the .blackbird package to this folder, or pass -EnrollmentPath <path>."
}

function Get-JsonPropertyValue {
    param(
        [Parameter(Mandatory = $true)]
        $Object,
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $null
    }

    return $property.Value
}

function Convert-BytesToHex {
    param([byte[]]$Bytes)

    return -join ($Bytes | ForEach-Object { $_.ToString("x2") })
}

function Get-EnrollmentOperatorFingerprints {
    param($Enrollment)

    $fingerprints = @()
    $singleFingerprint = Get-JsonPropertyValue -Object $Enrollment -Name "operatorFingerprint"
    $fingerprintList = Get-JsonPropertyValue -Object $Enrollment -Name "operatorFingerprints"

    if ($singleFingerprint) {
        $fingerprints += [string]$singleFingerprint
    }
    if ($fingerprintList) {
        foreach ($fingerprint in @($fingerprintList)) {
            $fingerprints += [string]$fingerprint
        }
    }

    $valid = @()
    foreach ($fingerprint in $fingerprints) {
        if (Test-HexFingerprint $fingerprint) {
            $lower = $fingerprint.ToLowerInvariant()
            if ($valid -notcontains $lower) {
                $valid += $lower
            }
        }
    }

    return @($valid)
}

function Get-EnrollmentSignatureMessage {
    param($Enrollment)

    $fingerprintList = Get-JsonPropertyValue -Object $Enrollment -Name "operatorFingerprints"
    $fingerprints = @()
    foreach ($fingerprint in @($fingerprintList)) {
        $fingerprints += [string]$fingerprint
    }

    $parts = @(
        "BLACKBIRD_VM_ENROLLMENT_SIGNATURE_V1",
        [string](Get-JsonPropertyValue -Object $Enrollment -Name "protocol"),
        [string](Get-JsonPropertyValue -Object $Enrollment -Name "kind"),
        [string](Get-JsonPropertyValue -Object $Enrollment -Name "enrollmentId"),
        [string](Get-JsonPropertyValue -Object $Enrollment -Name "machineName"),
        [string](Get-JsonPropertyValue -Object $Enrollment -Name "createdUtc"),
        [string](Get-JsonPropertyValue -Object $Enrollment -Name "operatorFingerprint"),
        ($fingerprints -join ","),
        [string](Get-JsonPropertyValue -Object $Enrollment -Name "serverOperatorFingerprint")
    )

    return ($parts -join "`n")
}

function Assert-EnrollmentSignature {
    param(
        $Enrollment,
        [string]$ExpectedFingerprint = ""
    )

    $serverFingerprint = [string](Get-JsonPropertyValue -Object $Enrollment -Name "serverOperatorFingerprint")
    $publicKeyBase64 = [string](Get-JsonPropertyValue -Object $Enrollment -Name "serverOperatorPublicKey")
    $algorithm = [string](Get-JsonPropertyValue -Object $Enrollment -Name "signatureAlgorithm")
    $signatureBase64 = [string](Get-JsonPropertyValue -Object $Enrollment -Name "enrollmentSignature")

    if (-not (Test-HexFingerprint $serverFingerprint) -or
        [string]::IsNullOrWhiteSpace($publicKeyBase64) -or
        [string]::IsNullOrWhiteSpace($signatureBase64) -or
        $algorithm -ne "ECDSA-P256-SHA256-FIXED") {
        throw "The enrollment package is unsigned or uses an unsupported signature format."
    }

    $normalizedServerFingerprint = $serverFingerprint.ToLowerInvariant()
    if (-not [string]::IsNullOrWhiteSpace($ExpectedFingerprint) -and
        $normalizedServerFingerprint -ne $ExpectedFingerprint.ToLowerInvariant()) {
        throw "The enrollment package server fingerprint does not match the expected server fingerprint."
    }

    try {
        $publicBytes = [Convert]::FromBase64String($publicKeyBase64)
        $signatureBytes = [Convert]::FromBase64String($signatureBase64)
    }
    catch {
        throw "The enrollment package signature material could not be decoded."
    }

    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $actualFingerprint = Convert-BytesToHex -Bytes ($sha256.ComputeHash($publicBytes))
    }
    finally {
        $sha256.Dispose()
    }
    if ($actualFingerprint -ne $normalizedServerFingerprint) {
        throw "The enrollment package public key does not match the server fingerprint."
    }

    $messageBytes = [Text.Encoding]::UTF8.GetBytes((Get-EnrollmentSignatureMessage -Enrollment $Enrollment))
    $key = $null
    $ecdsa = $null
    try {
        $key = [System.Security.Cryptography.CngKey]::Import(
            $publicBytes,
            [System.Security.Cryptography.CngKeyBlobFormat]::EccPublicBlob
        )
        $ecdsa = [System.Security.Cryptography.ECDsaCng]::new($key)
        try {
            $verified = $ecdsa.VerifyData(
                $messageBytes,
                $signatureBytes,
                [System.Security.Cryptography.HashAlgorithmName]::SHA256
            )
        }
        catch {
            $ecdsa.HashAlgorithm = [System.Security.Cryptography.CngAlgorithm]::Sha256
            $verified = $ecdsa.VerifyData($messageBytes, $signatureBytes)
        }
    }
    catch {
        throw "The enrollment package signature could not be verified."
    }
    finally {
        if ($null -ne $ecdsa) { $ecdsa.Dispose() }
        if ($null -ne $key) { $key.Dispose() }
    }

    if (-not $verified) {
        throw "The enrollment package signature is invalid."
    }

    return $normalizedServerFingerprint
}

function Test-EnrollmentHasAnySignatureFields {
    param($Enrollment)

    return -not [string]::IsNullOrWhiteSpace([string](Get-JsonPropertyValue -Object $Enrollment -Name "serverOperatorFingerprint")) -or
        -not [string]::IsNullOrWhiteSpace([string](Get-JsonPropertyValue -Object $Enrollment -Name "serverOperatorPublicKey")) -or
        -not [string]::IsNullOrWhiteSpace([string](Get-JsonPropertyValue -Object $Enrollment -Name "signatureAlgorithm")) -or
        -not [string]::IsNullOrWhiteSpace([string](Get-JsonPropertyValue -Object $Enrollment -Name "enrollmentSignature"))
}

function Test-EnrollmentHasCompleteSignatureFields {
    param($Enrollment)

    $serverFingerprint = [string](Get-JsonPropertyValue -Object $Enrollment -Name "serverOperatorFingerprint")
    $publicKeyBase64 = [string](Get-JsonPropertyValue -Object $Enrollment -Name "serverOperatorPublicKey")
    $algorithm = [string](Get-JsonPropertyValue -Object $Enrollment -Name "signatureAlgorithm")
    $signatureBase64 = [string](Get-JsonPropertyValue -Object $Enrollment -Name "enrollmentSignature")

    return (Test-HexFingerprint $serverFingerprint) -and
        -not [string]::IsNullOrWhiteSpace($publicKeyBase64) -and
        -not [string]::IsNullOrWhiteSpace($signatureBase64) -and
        $algorithm -eq "ECDSA-P256-SHA256-FIXED"
}

function Confirm-EnrollmentServerFingerprint {
    param(
        $Enrollment,
        [string]$ExpectedFingerprint = ""
    )

    if (-not (Test-EnrollmentHasCompleteSignatureFields -Enrollment $Enrollment)) {
        if ((Test-EnrollmentHasAnySignatureFields -Enrollment $Enrollment) -or
            -not [string]::IsNullOrWhiteSpace($ExpectedFingerprint)) {
            throw "The enrollment package is unsigned or uses an unsupported signature format."
        }

        Write-Warning "Enrollment package is unsigned; trusting the staged operator fingerprint(s) without package-signature verification."
        return ""
    }

    $serverFingerprint = Assert-EnrollmentSignature -Enrollment $Enrollment -ExpectedFingerprint $ExpectedFingerprint
    if (-not [string]::IsNullOrWhiteSpace($ExpectedFingerprint)) {
        return $serverFingerprint
    }

    Write-Host "Server operator fingerprint:"
    Write-Host "  $serverFingerprint"
    Write-Host ""
    $confirmation = Read-Host "Type the server operator fingerprint to trust this enrollment"
    if ($confirmation.Trim().ToLowerInvariant() -ne $serverFingerprint) {
        throw "Server operator fingerprint confirmation did not match."
    }
    return $serverFingerprint
}

function Read-EnrollmentFingerprints {
    param([string]$Path)

    $enrollment = Read-EnrollmentDocument -Path $Path
    return @(Get-EnrollmentOperatorFingerprints -Enrollment $enrollment)
}

function Read-EnrollmentDocument {
    param([string]$Path)

    $raw = Get-Content -Raw -LiteralPath $Path
    $trimmed = $raw.Trim()
    if ($trimmed.StartsWith("{")) {
        return $trimmed | ConvertFrom-Json
    }

    $lines = $trimmed -split "\r?\n"
    if ($lines.Count -lt 2 -or $lines[0].Trim() -ne "BLACKBIRD-VM-ENROLLMENT/1") {
        throw "The enrollment package format is not recognized."
    }

    $encoded = (($lines | Select-Object -Skip 1) -join "").Trim()
    try {
        $bytes = [Convert]::FromBase64String($encoded)
        $json = [Text.Encoding]::UTF8.GetString($bytes)
        return $json | ConvertFrom-Json
    }
    catch {
        throw "The enrollment package could not be decoded."
    }
}

function Find-VmPackageFile {
    param([string]$FileName)

    $candidates = @(
        (Join-Path $repoRoot $FileName),
        (Join-Path $repoRoot "Lib\NetworkServiceLayer\target\release\$FileName"),
        (Join-Path $repoRoot "x64\Release\$FileName"),
        (Join-Path $repoRoot "vcxproj\x64\Release\$FileName"),
        (Join-Path $repoRoot "x64\TEMPUS_DEBUG\$FileName"),
        (Join-Path $repoRoot "vcxproj\x64\TEMPUS_DEBUG\$FileName"),
        (Join-Path $repoRoot "x64\Debug\$FileName"),
        (Join-Path $repoRoot "vcxproj\x64\Debug\$FileName")
    )

    foreach ($candidate in $candidates) {
        $resolved = Resolve-Path -LiteralPath $candidate -ErrorAction SilentlyContinue
        if ($null -ne $resolved) {
            return $resolved.Path
        }
    }

    return $null
}

function Assert-VmPackageReady {
    $requiredFiles = @(
        "blackbird.sys",
        "BlackbirdController.exe",
        "BlackbirdNetSvc.exe",
        "BlackbirdPreviewHost.exe",
        "BlackbirdRunner.exe"
    )

    $missing = @()
    foreach ($fileName in $requiredFiles) {
        if (-not (Find-VmPackageFile -FileName $fileName)) {
            $missing += $fileName
        }
    }

    if ($missing.Count -gt 0) {
        throw "This folder is not a complete Blackbird VM package. Missing: $($missing -join ', '). Copy the built Blackbird files, including BlackbirdNetSvc.exe, BlackbirdPreviewHost.exe, and BlackbirdRunner.exe, then rerun this script."
    }
}

function Test-LocalTcpListen {
    param([int]$Port)

    $connection = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
    return $null -ne $connection
}

function Test-LocalUdpEndpoint {
    param([int]$Port)

    $endpoint = Get-NetUDPEndpoint -LocalPort $Port -ErrorAction SilentlyContinue | Select-Object -First 1
    return $null -ne $endpoint
}

function Show-BlackbirdNetworkDiagnostics {
    Write-Host ""
    Write-Host "Blackbird VM network diagnostics"
    Write-Host "--------------------------------"

    Write-Host "Controller service:"
    & sc.exe query BlackbirdController 2>&1 | ForEach-Object { Write-Host "  $_" }

    Write-Host ""
    Write-Host "Processes:"
    $processes = Get-Process -Name BlackbirdController, BlackbirdNetSvc -ErrorAction SilentlyContinue
    if ($processes) {
        $processes | ForEach-Object { Write-Host ("  {0} pid={1}" -f $_.ProcessName, $_.Id) }
    }
    else {
        Write-Host "  BlackbirdController/BlackbirdNetSvc are not running."
    }

    Write-Host ""
    Write-Host "Listening ports:"
    $netstatLines = & netstat.exe -ano 2>&1 | Where-Object { $_ -match "49371|49372|49373" }
    if ($netstatLines) {
        $netstatLines | ForEach-Object { Write-Host "  $_" }
    }
    else {
        Write-Host "  No Blackbird listener was found on UDP 49371 or TCP 49372/49373."
    }

    $logPath = Join-Path $env:ProgramData "Blackbird\Node\logs\netsvc.log"
    if (Test-Path -LiteralPath $logPath -PathType Leaf) {
        Write-Host ""
        Write-Host "NetSvc log tail: $logPath"
        Get-Content -LiteralPath $logPath -Tail 40 | ForEach-Object { Write-Host "  $_" }
    }
    else {
        Write-Host ""
        Write-Host "NetSvc log was not found at $logPath"
    }

    $controllerLogPath = Join-Path $env:ProgramData "Blackbird\Node\logs\controller.log"
    if (Test-Path -LiteralPath $controllerLogPath -PathType Leaf) {
        Write-Host ""
        Write-Host "Controller log tail: $controllerLogPath"
        Get-Content -LiteralPath $controllerLogPath -Tail 60 | ForEach-Object { Write-Host "  $_" }
    }
    else {
        Write-Host ""
        Write-Host "Controller log was not found at $controllerLogPath"
    }
}

function Wait-BlackbirdVmNetworkReady {
    param([int]$TimeoutSeconds = 30)

    $deadline = [DateTime]::UtcNow.AddSeconds([Math]::Max(5, $TimeoutSeconds))
    while ([DateTime]::UtcNow -lt $deadline) {
        $netSvc = Get-Process -Name BlackbirdNetSvc -ErrorAction SilentlyContinue | Select-Object -First 1
        $udpReady = Test-LocalUdpEndpoint -Port 49371
        $statusReady = Test-LocalTcpListen -Port 49372
        $commandReady = Test-LocalTcpListen -Port 49373

        if ($netSvc -and $udpReady -and $statusReady -and $commandReady) {
            Write-Host ""
            Write-Host "Blackbird VM network is ready."
            Write-Host "Discovery: UDP 49371"
            Write-Host "Status:    TCP 49372"
            Write-Host "Command:   TCP 49373"
            return
        }

        Start-Sleep -Milliseconds 750
    }

    Show-BlackbirdNetworkDiagnostics
    throw "Blackbird installed, but the VM discovery/control listeners did not come online. The server will not find this VM until BlackbirdNetSvc is running and ports 49371/49372/49373 are listening."
}

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script from an elevated PowerShell session inside the VM."
}

$resolvedEnrollment = Resolve-EnrollmentPath -RequestedPath $EnrollmentPath
$enrollment = Read-EnrollmentDocument -Path $resolvedEnrollment
$confirmedServerFingerprint = Confirm-EnrollmentServerFingerprint -Enrollment $enrollment -ExpectedFingerprint $ExpectedServerOperatorFingerprint
$fingerprints = @(Get-EnrollmentOperatorFingerprints -Enrollment $enrollment)
if ($fingerprints.Count -eq 0) {
    throw "The enrollment package does not contain a valid operatorFingerprint or operatorFingerprints value."
}
Assert-VmPackageReady

if (-not (Test-Path -LiteralPath $installer -PathType Leaf)) {
    throw "Blackbird installer was not found at $installer. Copy the whole Blackbird folder from the enrollment package."
}

Write-Host "Blackbird VM registration"
Write-Host "-------------------------"
Write-Host "Enrollment: $resolvedEnrollment"
if (-not [string]::IsNullOrWhiteSpace($confirmedServerFingerprint)) {
    Write-Host "Server operator fingerprint:"
    Write-Host "  $confirmedServerFingerprint"
}
else {
    Write-Host "Server operator fingerprint: unsigned legacy enrollment"
}
Write-Host "Trusted operator fingerprint(s):"
foreach ($fingerprint in $fingerprints) {
Write-Host "  $fingerprint"
}
Write-Host ""

Set-StrictMode -Off
& $installer -EnrollmentPath $resolvedEnrollment -ExpectedServerOperatorFingerprint $confirmedServerFingerprint -SkipEnrollmentPrompt @InstallerArgs
if (-not $?) {
    throw "Blackbird installer failed."
}

Wait-BlackbirdVmNetworkReady

Write-Host ""
Write-Host "Blackbird VM registration complete."
Write-Host "Use the server Machines page to scan/register this VM, then open the preview/control channel."
