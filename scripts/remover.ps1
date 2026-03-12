param(
    [string]$DriverName = "blackbird",
    [string]$ControllerName = "BlackbirdController",
    [string[]]$LegacyDriverNames = @("sleepwlkr", "sleepwalker"),
    [string[]]$LegacyControllerNames = @("SleepwlkrController", "SleepwalkerController")
)

$ErrorActionPreference = "Stop"

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script as Administrator."
}

function Remove-ServiceBestEffort {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServiceName,
        [switch]$TryFltUnload
    )

    if ([string]::IsNullOrWhiteSpace($ServiceName)) {
        return
    }

    & sc.exe stop $ServiceName | Out-Null
    if ($TryFltUnload) {
        & fltmc.exe unload $ServiceName | Out-Null
    }
    & sc.exe delete $ServiceName | Out-Null
    Remove-Item -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName" -Recurse -Force -ErrorAction SilentlyContinue
}

$allDriverNames = @($DriverName) + $LegacyDriverNames | Sort-Object -Unique
$allControllerNames = @($ControllerName) + $LegacyControllerNames | Sort-Object -Unique

foreach ($svc in $allControllerNames) {
    Remove-ServiceBestEffort -ServiceName $svc
}

foreach ($svc in $allDriverNames) {
    Remove-ServiceBestEffort -ServiceName $svc -TryFltUnload
}

$driverBinaries = @("blackbird.sys", "sleepwlkr.sys", "sleepwalker.sys") | Sort-Object -Unique
foreach ($name in $driverBinaries) {
    $driverDst = Join-Path $env:windir ("System32\drivers\" + $name)
    Remove-Item -LiteralPath $driverDst -Force -ErrorAction SilentlyContinue
}

$controllerRoots = @(
    (Join-Path -Path $env:ProgramFiles -ChildPath "Blackbird"),
    (Join-Path -Path $env:ProgramFiles -ChildPath "Sleepwalker")
)
foreach ($root in $controllerRoots) {
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host "[*] Removed services and binaries for driver(s): $($allDriverNames -join ', ') / controller(s): $($allControllerNames -join ', ')"
