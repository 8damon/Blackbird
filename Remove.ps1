param(
    [string]$DriverName = "sleepwlkr",
    [string]$ControllerName = "SleepwlkrController"
)

$ErrorActionPreference = "Stop"

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script as Administrator."
}

$driverDst = Join-Path $env:windir "System32\drivers\sleepwlkr.sys"
$controllerDst = Join-Path (Join-Path $env:ProgramFiles "Sleepwalker") "SleepwlkrController.exe"

sc.exe stop $ControllerName | Out-Null
sc.exe delete $ControllerName | Out-Null

sc.exe stop $DriverName | Out-Null
sc.exe delete $DriverName | Out-Null

Remove-Item -LiteralPath $controllerDst -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $driverDst -Force -ErrorAction SilentlyContinue

Write-Host "[*] Removed services and binaries for $DriverName + $ControllerName"
