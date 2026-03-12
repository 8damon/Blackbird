param(
    [switch]$Uninstall,
    [string]$ServiceName = "BlackbirdController",
    [string]$DisplayName = "Blackbird Controller Service",
    [string]$BinaryPath = ""
)

$ErrorActionPreference = "Stop"

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script from an elevated PowerShell session."
}

if ([string]::IsNullOrWhiteSpace($BinaryPath)) {
    $repoRoot = Split-Path -Parent $PSScriptRoot
    $BinaryPath = Join-Path $repoRoot "x64\\Release\\BlackbirdController.exe"
}

if ($Uninstall) {
    sc.exe stop $ServiceName | Out-Null
    sc.exe delete $ServiceName | Out-Null
    Write-Host "[*] Removed service '$ServiceName'."
    exit 0
}

if (-not (Test-Path -LiteralPath $BinaryPath)) {
    throw "Controller binary not found: $BinaryPath"
}

sc.exe stop $ServiceName | Out-Null
sc.exe delete $ServiceName | Out-Null

sc.exe create $ServiceName binPath= "\"$BinaryPath\"" start= auto obj= LocalSystem DisplayName= "\"$DisplayName\"" | Out-Null
sc.exe failure $ServiceName reset= 60 actions= restart/5000/restart/5000/restart/5000 | Out-Null
sc.exe start $ServiceName | Out-Null

Write-Host "[*] Installed and started '$ServiceName'."
Write-Host "    Binary: $BinaryPath"
