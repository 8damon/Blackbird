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

function Write-VerboseLog {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    Write-Host $Message -ForegroundColor DarkGray
}

function Write-InfoLog {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    Write-Host ("[info] {0}" -f $Message) -ForegroundColor Gray
}

function Format-CommandArgs {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    return ($Arguments | ForEach-Object {
            if ($_ -match '\s') { ('"{0}"' -f $_) } else { $_ }
        }) -join ' '
}

function Invoke-ScBestEffort {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,
        [int[]]$AllowedExitCodes = @(0)
    )

    $cmdText = Format-CommandArgs -Arguments $Arguments
    Write-VerboseLog "sc.exe $cmdText"
    $output = & sc.exe @Arguments 2>&1
    $exitCode = $LASTEXITCODE
    if ($output) {
        foreach ($line in $output) {
            Write-VerboseLog "sc.exe> $line"
        }
    }
    Write-VerboseLog "sc.exe exit=$exitCode allowed=$($AllowedExitCodes -join ',')"
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
        Write-VerboseLog "Unlock check skipped; file not present: $Path"
        return $true
    }

    Write-VerboseLog "Waiting for file unlock: $Path (timeout ${TimeoutSeconds}s)"
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $attempt = 0
    while ((Get-Date) -lt $deadline) {
        $attempt++
        try {
            $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
            $stream.Close()
            Write-VerboseLog "File unlocked after $attempt attempt(s): $Path"
            return $true
        }
        catch {
            if ($attempt -eq 1 -or ($attempt % 5) -eq 0) {
                Write-VerboseLog "File still locked on attempt ${attempt}: $Path"
            }
            Start-Sleep -Milliseconds 300
        }
    }

    Write-VerboseLog "Unlock wait timed out: $Path"
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

    Write-InfoLog "Removing service artifacts for $ServiceName"
    Invoke-ScBestEffort -Arguments @("config", $ServiceName, "start=", "disabled") -AllowedExitCodes @(0, 5, 1060)
    Invoke-ScBestEffort -Arguments @("stop", $ServiceName) -AllowedExitCodes @(0, 5, 1060, 1062)
    if ($TryFltUnload) {
        Write-VerboseLog "fltmc.exe unload $ServiceName"
        $fltOut = & fltmc.exe unload $ServiceName 2>&1
        if ($fltOut) {
            foreach ($line in $fltOut) {
                Write-VerboseLog "fltmc> $line"
            }
        }
        Write-VerboseLog "fltmc unload exit=$LASTEXITCODE"
    }
    Invoke-ScBestEffort -Arguments @("delete", $ServiceName) -AllowedExitCodes @(0, 5, 1060, 1072)
    Remove-Item -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName" -Recurse -Force -ErrorAction SilentlyContinue
}

function Test-ServiceExists {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServiceName
    )

    Write-VerboseLog "Checking service existence: $ServiceName"
    & sc.exe query $ServiceName 2>&1 | Out-Null
    Write-VerboseLog "Service $ServiceName exists=$($LASTEXITCODE -eq 0)"
    return $LASTEXITCODE -eq 0
}

function Wait-ServiceRemoved {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServiceName,
        [int]$TimeoutSeconds = 20
    )

    Write-VerboseLog "Waiting for service removal: $ServiceName (timeout ${TimeoutSeconds}s)"
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $attempt = 0

    while ((Get-Date) -lt $deadline) {
        $attempt++
        & sc.exe query $ServiceName 2>&1 | Out-Null
        $queryExit = $LASTEXITCODE

        if ($queryExit -eq 1060) {
            Write-VerboseLog "Service removed after $attempt attempt(s): $ServiceName"
            return $true
        }

        if ($attempt -eq 1 -or ($attempt % 5) -eq 0) {
            Write-VerboseLog "Service still present on attempt ${attempt}: $ServiceName (sc exit $queryExit)"
        }

        Start-Sleep -Milliseconds 500
    }

    Write-VerboseLog "Service removal wait timed out: $ServiceName"
    return $false
}

function Assert-ServiceGoneOrWarn {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServiceName,
        [int]$TimeoutSeconds = 20
    )

    if (Wait-ServiceRemoved -ServiceName $ServiceName -TimeoutSeconds $TimeoutSeconds) {
        return
    }

    Write-Host "    Service '$ServiceName' is still present in SCM after delete." -ForegroundColor Yellow
    Write-Host "    This usually means another process still has the service object open." -ForegroundColor Yellow
    Write-Host "    Reinstall may still succeed once the name becomes reusable." -ForegroundColor Yellow
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

    Write-InfoLog "Deleting $Label at $Path"
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

function Remove-FirewallRuleIfPresent {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DisplayName
    )

    Write-VerboseLog "Removing firewall rule if present: $DisplayName"
    Get-NetFirewallRule -DisplayName $DisplayName -ErrorAction SilentlyContinue |
        Remove-NetFirewallRule -ErrorAction SilentlyContinue
}

$totalStages = 6
$activity = "Blackbird removal"
$driverDst = Join-Path $env:windir ("System32\drivers\" + $DriverName + ".sys")
$controllerRoot = Join-Path -Path $env:ProgramFiles -ChildPath "Blackbird"
$controllerDst = Join-Path $controllerRoot "BlackbirdController.exe"
$sensorCoreDst = Join-Path $controllerRoot "J58.dll"

Write-Host ""
Write-Host "Blackbird Remover"
Write-Host "-----------------"

Write-Stage -Index 1 -Total $totalStages -Activity $activity -Status "Removing driver service"
Remove-ServiceBestEffort -ServiceName $DriverName -TryFltUnload
Assert-ServiceGoneOrWarn -ServiceName $DriverName -TimeoutSeconds 20

Write-Stage -Index 2 -Total $totalStages -Activity $activity -Status "Removing controller service"
Write-Host "    Stopping and deleting service '$ControllerName' after driver teardown..." -ForegroundColor DarkCyan
Remove-ServiceBestEffort -ServiceName $ControllerName
Assert-ServiceGoneOrWarn -ServiceName $ControllerName -TimeoutSeconds 20

Write-Stage -Index 3 -Total $totalStages -Activity $activity -Status "Deleting installed binaries"
if (-not (Wait-UntilFileUnlocked -Path $driverDst -TimeoutSeconds 20)) {
    throw "$driverDst is still locked after service stop/unload. Reboot then rerun remover."
}
Remove-PathIfPresent -Path $driverDst -Label "driver binary"
Assert-Removal -Condition (-not (Test-Path -LiteralPath $driverDst)) -FailureMessage "Driver binary still exists: $driverDst"

Write-Stage -Index 4 -Total $totalStages -Activity $activity -Status "Deleting controller files"
if (-not (Wait-UntilFileUnlocked -Path $controllerDst -TimeoutSeconds 20)) {
    throw "$controllerDst is still locked after controller service stop. Reboot then rerun remover."
}
if (-not (Wait-UntilFileUnlocked -Path $sensorCoreDst -TimeoutSeconds 20)) {
    throw "$sensorCoreDst is still locked after controller service stop. Reboot then rerun remover."
}
Remove-PathIfPresent -Path $controllerRoot -Label "controller directory"
Assert-Removal -Condition (-not (Test-Path -LiteralPath $controllerRoot)) -FailureMessage "Controller directory still exists: $controllerRoot"

Write-Stage -Index 5 -Total $totalStages -Activity $activity -Status "Removing firewall rules"
Remove-FirewallRuleIfPresent -DisplayName "Blackbird Operator UDP Discovery"
Remove-FirewallRuleIfPresent -DisplayName "Blackbird Operator TCP Status"
Remove-FirewallRuleIfPresent -DisplayName "Blackbird Operator TCP Command"
Remove-FirewallRuleIfPresent -DisplayName "Blackbird Operator ICMPv4"

Write-Stage -Index 6 -Total $totalStages -Activity $activity -Status "Removal complete"
Write-VerboseLog "Driver and controller teardown finished"

Write-Progress -Id 1 -Activity $activity -Completed
Write-Host "[*] Removed services and binaries for driver '$DriverName' and controller '$ControllerName'"

