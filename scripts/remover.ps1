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

function Invoke-ScBestEffort {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,
        [int[]]$AllowedExitCodes = @(0)
    )

    $output = & sc.exe @Arguments 2>&1
    $exitCode = $LASTEXITCODE
    if ($AllowedExitCodes -notcontains $exitCode) {
        $detail = (($output | ForEach-Object { "$_" }) -join [Environment]::NewLine).Trim()
        if (-not [string]::IsNullOrWhiteSpace($detail)) {
            Write-Host "    sc.exe $($Arguments -join ' ') -> exit $exitCode" -ForegroundColor Yellow
            Write-Host "    $detail" -ForegroundColor Yellow
        }
    }
}

function Wait-UntilFileUnlocked {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [int]$TimeoutSeconds = 20
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return $true
    }

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        try {
            $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
            $stream.Close()
            return $true
        }
        catch {
            Start-Sleep -Milliseconds 300
        }
    }

    return $false
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

    Invoke-ScBestEffort -Arguments @("config", $ServiceName, "start=", "disabled") -AllowedExitCodes @(0, 5, 1060)
    Invoke-ScBestEffort -Arguments @("stop", $ServiceName) -AllowedExitCodes @(0, 5, 1060, 1062)
    if ($TryFltUnload) {
        & fltmc.exe unload $ServiceName 2>&1 | Out-Null
    }
    Invoke-ScBestEffort -Arguments @("delete", $ServiceName) -AllowedExitCodes @(0, 5, 1060, 1072)
    Remove-Item -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName" -Recurse -Force -ErrorAction SilentlyContinue
}

$allDriverNames = @($DriverName) + $LegacyDriverNames | Sort-Object -Unique
$allControllerNames = @($ControllerName) + $LegacyControllerNames | Sort-Object -Unique

# Kill stale controller processes first. Some builds keep the .sys open from user mode.
foreach ($proc in @("BlackbirdController", "SleepwlkrController", "SleepwalkerController")) {
    Get-Process -Name $proc -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
}

foreach ($svc in $allControllerNames) {
    Remove-ServiceBestEffort -ServiceName $svc
}

foreach ($svc in $allDriverNames) {
    Remove-ServiceBestEffort -ServiceName $svc -TryFltUnload
}

$driverBinaries = @("blackbird.sys", "sleepwlkr.sys", "sleepwalker.sys") | Sort-Object -Unique
foreach ($name in $driverBinaries) {
    $driverDst = Join-Path $env:windir ("System32\drivers\" + $name)
    if (-not (Wait-UntilFileUnlocked -Path $driverDst -TimeoutSeconds 20)) {
        Write-Host "[!] $driverDst is still locked after service stop/unload. Reboot then rerun remover." -ForegroundColor Yellow
        continue
    }
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
