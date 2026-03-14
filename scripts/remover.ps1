param(
    [string]$DriverName = "blackbird",
    [string]$ControllerName = "BlackbirdController"
)

$ErrorActionPreference = "Stop"

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script as Administrator."
}

function Write-Stage {
    param(
        [Parameter(Mandatory = $true)]
        [int]$Index,
        [Parameter(Mandatory = $true)]
        [int]$Total,
        [Parameter(Mandatory = $true)]
        [string]$Activity,
        [Parameter(Mandatory = $true)]
        [string]$Status
    )

    $percent = [Math]::Floor(($Index / $Total) * 100)
    Write-Progress -Id 1 -Activity $Activity -Status $Status -PercentComplete $percent
    Write-Host ""
    Write-Host ("[{0}/{1}] {2}" -f $Index, $Total, $Status) -ForegroundColor Cyan
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

function Test-ServiceExists {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServiceName
    )

    & sc.exe query $ServiceName 2>&1 | Out-Null
    return $LASTEXITCODE -eq 0
}

function Remove-PathIfPresent {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [string]$Label
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        Write-Host "    $Label not present: $Path" -ForegroundColor DarkYellow
        return
    }

    Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
    Write-Host "    Removed ${Label}: $Path" -ForegroundColor Green
}

function Assert-Removal {
    param(
        [Parameter(Mandatory = $true)]
        [bool]$Condition,
        [Parameter(Mandatory = $true)]
        [string]$FailureMessage
    )

    if (-not $Condition) {
        throw $FailureMessage
    }
}

$totalStages = 5
$activity = "Blackbird removal"
$driverDst = Join-Path $env:windir ("System32\drivers\" + $DriverName + ".sys")
$controllerRoot = Join-Path -Path $env:ProgramFiles -ChildPath "Blackbird"

Write-Host ""
Write-Host "Blackbird Remover"
Write-Host "-----------------"

Write-Stage -Index 1 -Total $totalStages -Activity $activity -Status "Stopping controller processes"
foreach ($proc in @("BlackbirdController")) {
    Get-Process -Name $proc -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
}

Write-Stage -Index 2 -Total $totalStages -Activity $activity -Status "Removing controller service"
Remove-ServiceBestEffort -ServiceName $ControllerName
Assert-Removal -Condition (-not (Test-ServiceExists -ServiceName $ControllerName)) -FailureMessage "Controller service '$ControllerName' still exists after removal."

Write-Stage -Index 3 -Total $totalStages -Activity $activity -Status "Removing driver service"
Remove-ServiceBestEffort -ServiceName $DriverName -TryFltUnload
Assert-Removal -Condition (-not (Test-ServiceExists -ServiceName $DriverName)) -FailureMessage "Driver service '$DriverName' still exists after removal."

Write-Stage -Index 4 -Total $totalStages -Activity $activity -Status "Deleting installed binaries"
if (-not (Wait-UntilFileUnlocked -Path $driverDst -TimeoutSeconds 20)) {
    throw "$driverDst is still locked after service stop/unload. Reboot then rerun remover."
}
Remove-PathIfPresent -Path $driverDst -Label "driver binary"
Assert-Removal -Condition (-not (Test-Path -LiteralPath $driverDst)) -FailureMessage "Driver binary still exists: $driverDst"

Write-Stage -Index 5 -Total $totalStages -Activity $activity -Status "Deleting controller files"
Remove-PathIfPresent -Path $controllerRoot -Label "controller directory"
Assert-Removal -Condition (-not (Test-Path -LiteralPath $controllerRoot)) -FailureMessage "Controller directory still exists: $controllerRoot"

Write-Progress -Id 1 -Activity $activity -Completed
Write-Host "[*] Removed services and binaries for driver '$DriverName' and controller '$ControllerName'"
