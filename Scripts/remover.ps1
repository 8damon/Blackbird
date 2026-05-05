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

    return [pscustomobject]@{
        ExitCode = $exitCode
        Output   = @($output | ForEach-Object { "$_" })
    }
}

function Invoke-BlackbirdRuntimeDisarm {
    param(
        [Parameter(Mandatory = $true)]
        [string]$SensorCorePath
    )

    if (-not (Test-Path -LiteralPath $SensorCorePath)) {
        Write-InfoLog "Runtime disarm skipped; J58.dll is not present at $SensorCorePath."
        return
    }

    if ($null -eq ("BlackbirdRuntimeDisarmNative" -as [type])) {
        Add-Type -Language CSharp -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class BlackbirdRuntimeDisarmNative
{
    [DllImport("kernel32.dll", EntryPoint = "SetDllDirectoryW", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool SetDllDirectory(string path);

    [DllImport("J58.dll", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    public static extern IntPtr BkscOpenControlDevice();

    [DllImport("J58.dll", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool BkscSetRuntimeConfig(IntPtr device, UInt32 flags, UInt32 mask);

    [DllImport("J58.dll", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool BkscCloseControlDevice(IntPtr device);
}
'@
    }

    $sensorDir = Split-Path -Path $SensorCorePath -Parent
    $invalidHandle = [IntPtr](-1)
    $device = [IntPtr]::Zero
    $runtimeMask = [uint32]0x0000003F
    $runtimeFlags = [uint32]0x00000030

    try {
        [void][BlackbirdRuntimeDisarmNative]::SetDllDirectory($sensorDir)
        $device = [BlackbirdRuntimeDisarmNative]::BkscOpenControlDevice()
        if ($device -eq [IntPtr]::Zero -or $device -eq $invalidHandle) {
            $openErr = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Host "    Runtime disarm could not open the driver control device (err=$openErr)." -ForegroundColor Yellow
            return
        }

        if ([BlackbirdRuntimeDisarmNative]::BkscSetRuntimeConfig($device, $runtimeFlags, $runtimeMask)) {
            Write-InfoLog ("Runtime disarmed before service stop flags=0x{0:X8} mask=0x{1:X8}" -f $runtimeFlags, $runtimeMask)
        }
        else {
            $setErr = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Host "    Runtime disarm failed before service stop (err=$setErr)." -ForegroundColor Yellow
        }
    }
    finally {
        if ($device -ne [IntPtr]::Zero -and $device -ne $invalidHandle) {
            [void][BlackbirdRuntimeDisarmNative]::BkscCloseControlDevice($device)
        }
        [void][BlackbirdRuntimeDisarmNative]::SetDllDirectory($null)
    }
}

function Get-ScNumber {
    param(
        [string]$Text,
        [string]$Name
    )

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return 0
    }

    $pattern = "(?m)^\s*$([Regex]::Escape($Name))\s*:\s*(0x[0-9A-Fa-f]+|\d+)"
    if ($Text -match $pattern) {
        $raw = $matches[1]
        if ($raw.StartsWith("0x", [System.StringComparison]::OrdinalIgnoreCase)) {
            return [Convert]::ToInt32($raw.Substring(2), 16)
        }
        return [int]$raw
    }

    return 0
}

function Get-ServiceSnapshot {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServiceName
    )

    $output = & sc.exe queryex $ServiceName 2>&1
    $exitCode = $LASTEXITCODE
    $text = (($output | ForEach-Object { "$_" }) -join [Environment]::NewLine)
    $stateCode = 0
    $stateName = "ABSENT"

    if ($exitCode -eq 0 -and $text -match "STATE\s*:\s*(\d+)\s+([A-Z_]+)") {
        $stateCode = [int]$matches[1]
        $stateName = $matches[2]
    }

    return [pscustomobject]@{
        Name       = $ServiceName
        Exists     = ($exitCode -eq 0)
        ExitCode   = $exitCode
        StateCode  = $stateCode
        StateName  = $stateName
        CheckPoint = (Get-ScNumber -Text $text -Name "CHECKPOINT")
        WaitHint   = (Get-ScNumber -Text $text -Name "WAIT_HINT")
        ProcessId  = (Get-ScNumber -Text $text -Name "PID")
        Text       = $text
    }
}

function Get-ServicePollDelayMs {
    param(
        [int]$WaitHint
    )

    if ($WaitHint -gt 0) {
        return [Math]::Min([Math]::Max([int]($WaitHint / 4), 250), 2000)
    }

    return 500
}

function Wait-ServiceState {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServiceName,
        [Parameter(Mandatory = $true)]
        [string[]]$DesiredStates,
        [int]$TimeoutSeconds = 30,
        [switch]$AbsentIsSuccess
    )

    $deadline = (Get-Date).AddSeconds([Math]::Max(1, $TimeoutSeconds))
    $lastState = ""
    $lastCheckpoint = -1
    $attempt = 0
    $lastSnapshot = $null

    while ((Get-Date) -lt $deadline) {
        $attempt++
        $snapshot = Get-ServiceSnapshot -ServiceName $ServiceName
        $lastSnapshot = $snapshot

        if (-not $snapshot.Exists) {
            if ($AbsentIsSuccess) {
                Write-VerboseLog "Service absent while waiting for state: $ServiceName"
                return $true
            }
            return $false
        }

        if ($DesiredStates -contains $snapshot.StateName) {
            Write-VerboseLog "Service $ServiceName reached $($snapshot.StateName) after $attempt poll(s)"
            return $true
        }

        $changed = ($snapshot.StateName -ne $lastState) -or ($snapshot.CheckPoint -ne $lastCheckpoint)
        if ($changed -or $attempt -eq 1) {
            Write-VerboseLog ("Service {0} state={1} checkpoint=0x{2:X} waitHint={3}ms pid={4}" -f `
                    $ServiceName, $snapshot.StateName, $snapshot.CheckPoint, $snapshot.WaitHint, $snapshot.ProcessId)
            $lastState = $snapshot.StateName
            $lastCheckpoint = $snapshot.CheckPoint
        }

        Start-Sleep -Milliseconds (Get-ServicePollDelayMs -WaitHint $snapshot.WaitHint)
    }

    if ($null -ne $lastSnapshot) {
        Write-VerboseLog "Timed out waiting for $ServiceName. Last state=$($lastSnapshot.StateName) pid=$($lastSnapshot.ProcessId)"
    }

    return $false
}

function Wait-ServiceRemoved {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServiceName,
        [int]$TimeoutSeconds = 30
    )

    Write-VerboseLog "Waiting for service removal: $ServiceName (timeout ${TimeoutSeconds}s)"
    $deadline = (Get-Date).AddSeconds([Math]::Max(1, $TimeoutSeconds))
    $attempt = 0
    $lastExit = 0

    while ((Get-Date) -lt $deadline) {
        $attempt++
        $snapshot = Get-ServiceSnapshot -ServiceName $ServiceName
        $lastExit = $snapshot.ExitCode

        if (-not $snapshot.Exists) {
            Write-VerboseLog "Service removed after $attempt poll(s): $ServiceName"
            return $true
        }

        if ($attempt -eq 1 -or ($attempt % 6) -eq 0) {
            Write-VerboseLog ("Service still present: {0} state={1} pid={2} queryExit={3}" -f `
                    $ServiceName, $snapshot.StateName, $snapshot.ProcessId, $snapshot.ExitCode)
        }

        Start-Sleep -Milliseconds (Get-ServicePollDelayMs -WaitHint $snapshot.WaitHint)
    }

    Write-VerboseLog "Service removal timed out: $ServiceName (last query exit $lastExit)"
    return $false
}

function Stop-ServiceForRemoval {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServiceName,
        [switch]$TryFltUnload,
        [switch]$KillOwnProcessOnTimeout,
        [int]$TimeoutSeconds = 35
    )

    $snapshot = Get-ServiceSnapshot -ServiceName $ServiceName
    if (-not $snapshot.Exists) {
        Write-InfoLog "Service '$ServiceName' is not installed."
        return
    }

    Invoke-ScBestEffort -Arguments @("config", $ServiceName, "start=", "disabled") -AllowedExitCodes @(0, 5, 1060) | Out-Null

    if ($snapshot.StateName -eq "STOPPED") {
        Write-InfoLog "Service '$ServiceName' already stopped."
        return
    }

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

    $snapshot = Get-ServiceSnapshot -ServiceName $ServiceName
    if ($snapshot.Exists -and $snapshot.StateName -ne "STOPPED") {
        Invoke-ScBestEffort -Arguments @("stop", $ServiceName) -AllowedExitCodes @(0, 5, 1052, 1060, 1062) | Out-Null
    }

    if (Wait-ServiceState -ServiceName $ServiceName -DesiredStates @("STOPPED") -TimeoutSeconds $TimeoutSeconds -AbsentIsSuccess) {
        return
    }

    $snapshot = Get-ServiceSnapshot -ServiceName $ServiceName
    if ($KillOwnProcessOnTimeout -and $snapshot.Exists -and $snapshot.ProcessId -gt 0) {
        Write-Host "    Service '$ServiceName' did not stop; terminating service process pid=$($snapshot.ProcessId)." -ForegroundColor Yellow
        Stop-Process -Id $snapshot.ProcessId -Force -ErrorAction SilentlyContinue
        if (Wait-ServiceState -ServiceName $ServiceName -DesiredStates @("STOPPED") -TimeoutSeconds 10 -AbsentIsSuccess) {
            return
        }
    }

    $latest = Get-ServiceSnapshot -ServiceName $ServiceName
    throw "Service '$ServiceName' did not stop cleanly. Last SCM state: $($latest.StateName), pid=$($latest.ProcessId).`n$($latest.Text)"
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

function Remove-ServiceProperly {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServiceName,
        [switch]$TryFltUnload,
        [switch]$KillOwnProcessOnTimeout
    )

    if ([string]::IsNullOrWhiteSpace($ServiceName)) {
        return
    }

    Write-InfoLog "Stopping service '$ServiceName'"
    Stop-ServiceForRemoval -ServiceName $ServiceName -TryFltUnload:$TryFltUnload -KillOwnProcessOnTimeout:$KillOwnProcessOnTimeout

    $snapshot = Get-ServiceSnapshot -ServiceName $ServiceName
    if (-not $snapshot.Exists) {
        Remove-Item -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName" -Recurse -Force -ErrorAction SilentlyContinue
        return
    }
    if ($snapshot.StateName -ne "STOPPED") {
        throw "Refusing to delete service '$ServiceName' while SCM state is $($snapshot.StateName)."
    }

    Write-InfoLog "Deleting service '$ServiceName'"
    $delete = Invoke-ScBestEffort -Arguments @("delete", $ServiceName) -AllowedExitCodes @(0, 1060, 1072)
    if ($delete.ExitCode -eq 5) {
        throw "Access denied deleting service '$ServiceName'. Run elevated and close service management tools."
    }

    if (-not (Wait-ServiceRemoved -ServiceName $ServiceName -TimeoutSeconds 35)) {
        $latest = Get-ServiceSnapshot -ServiceName $ServiceName
        Write-Host "    Service '$ServiceName' is still present in SCM after delete." -ForegroundColor Yellow
        Write-Host "    Close Services.msc, Process Explorer, or any service handle owners and rerun." -ForegroundColor Yellow
        throw "Service '$ServiceName' remained after delete. Last state=$($latest.StateName), pid=$($latest.ProcessId)."
    }

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

function Restore-RegistryValueFromBackup {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TargetPath,
        [Parameter(Mandatory = $true)]
        [string]$BackupPath,
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $backup = Get-ItemProperty -LiteralPath $BackupPath -ErrorAction SilentlyContinue
    if ($null -eq $backup) {
        return
    }

    $presentProperty = $backup.PSObject.Properties["${Name}_Present"]
    if ($null -eq $presentProperty) {
        Write-Host "    CrashControl backup is missing metadata for $Name; leaving current value unchanged." -ForegroundColor Yellow
        return
    }

    if ([int]$presentProperty.Value -eq 0) {
        Remove-ItemProperty -Path $TargetPath -Name $Name -Force -ErrorAction SilentlyContinue
        Write-InfoLog "Removed CrashControl value $Name; it was absent before Blackbird installed."
        return
    }

    $kindProperty = $backup.PSObject.Properties["${Name}_Kind"]
    $valueProperty = $backup.PSObject.Properties["${Name}_Value"]
    if ($null -eq $kindProperty -or $null -eq $valueProperty) {
        Write-Host "    CrashControl backup is incomplete for $Name; leaving current value unchanged." -ForegroundColor Yellow
        return
    }

    $kind = [string]$kindProperty.Value
    $valueText = [string]$valueProperty.Value
    switch ($kind) {
        "DWord" {
            New-ItemProperty -Path $TargetPath -Name $Name -PropertyType DWord -Value ([int]$valueText) -Force | Out-Null
        }
        "QWord" {
            New-ItemProperty -Path $TargetPath -Name $Name -PropertyType QWord -Value ([long]$valueText) -Force | Out-Null
        }
        "ExpandString" {
            New-ItemProperty -Path $TargetPath -Name $Name -PropertyType ExpandString -Value $valueText -Force | Out-Null
        }
        "String" {
            New-ItemProperty -Path $TargetPath -Name $Name -PropertyType String -Value $valueText -Force | Out-Null
        }
        default {
            Write-Host "    Unsupported CrashControl backup type '$kind' for $Name; restoring as string." -ForegroundColor Yellow
            New-ItemProperty -Path $TargetPath -Name $Name -PropertyType String -Value $valueText -Force | Out-Null
        }
    }
    Write-InfoLog "Restored CrashControl value $Name"
}

function Restore-BlackbirdCrashDumpSettings {
    $crashControlKey = "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl"
    $backupKey = "HKLM:\SOFTWARE\Blackbird\Installer\CrashControlBackup"
    $managedValues = @(
        "CrashDumpEnabled",
        "AlwaysKeepMemoryDump",
        "LogEvent",
        "DumpFile",
        "MinidumpDir"
    )

    if (-not (Test-Path -LiteralPath $backupKey)) {
        Write-InfoLog "No Blackbird crash dump policy backup found; CrashControl settings left unchanged."
        return
    }

    if (-not (Test-Path -LiteralPath $crashControlKey)) {
        New-Item -Path $crashControlKey -Force | Out-Null
    }

    foreach ($name in $managedValues) {
        Restore-RegistryValueFromBackup -TargetPath $crashControlKey -BackupPath $backupKey -Name $name
    }

    Remove-Item -LiteralPath $backupKey -Recurse -Force -ErrorAction SilentlyContinue
    Write-InfoLog "Restored pre-Blackbird Windows crash dump policy."
}

$totalStages = 7
$activity = "Blackbird removal"
$driverDst = Join-Path $env:windir ("System32\drivers\" + $DriverName + ".sys")
$controllerRoot = Join-Path -Path $env:ProgramFiles -ChildPath "Blackbird"
$controllerDst = Join-Path $controllerRoot "BlackbirdController.exe"
$netSvcDst = Join-Path $controllerRoot "BlackbirdNetSvc.exe"
$previewHostDst = Join-Path $controllerRoot "BlackbirdPreviewHost.exe"
$runnerDst = Join-Path $controllerRoot "BlackbirdRunner.exe"
$sensorCoreDst = Join-Path $controllerRoot "J58.dll"
$hookDllDst = Join-Path $controllerRoot "SR71.dll"

Write-Host ""
Write-Host "Blackbird Remover"
Write-Host "-----------------"

Invoke-BlackbirdRuntimeDisarm -SensorCorePath $sensorCoreDst

Write-Stage -Index 1 -Total $totalStages -Activity $activity -Status "Removing controller service"
Write-Host "    Stopping controller first so it releases driver handles..." -ForegroundColor DarkCyan
Remove-ServiceProperly -ServiceName $ControllerName -KillOwnProcessOnTimeout

Write-Stage -Index 2 -Total $totalStages -Activity $activity -Status "Removing driver service"
Write-Host "    Unloading minifilter after controller teardown..." -ForegroundColor DarkCyan
Remove-ServiceProperly -ServiceName $DriverName -TryFltUnload

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
if (-not (Wait-UntilFileUnlocked -Path $netSvcDst -TimeoutSeconds 20)) {
    throw "$netSvcDst is still locked after controller service stop. Reboot then rerun remover."
}
if (-not (Wait-UntilFileUnlocked -Path $previewHostDst -TimeoutSeconds 20)) {
    throw "$previewHostDst is still locked after controller service stop. Reboot then rerun remover."
}
if (-not (Wait-UntilFileUnlocked -Path $runnerDst -TimeoutSeconds 20)) {
    throw "$runnerDst is still locked after controller service stop. Reboot then rerun remover."
}
if (-not (Wait-UntilFileUnlocked -Path $sensorCoreDst -TimeoutSeconds 20)) {
    throw "$sensorCoreDst is still locked after controller service stop. Reboot then rerun remover."
}
if (-not (Wait-UntilFileUnlocked -Path $hookDllDst -TimeoutSeconds 20)) {
    throw "$hookDllDst is still locked after controller service stop. Reboot then rerun remover."
}
Remove-PathIfPresent -Path $controllerRoot -Label "controller directory"
Assert-Removal -Condition (-not (Test-Path -LiteralPath $controllerRoot)) -FailureMessage "Controller directory still exists: $controllerRoot"

Write-Stage -Index 5 -Total $totalStages -Activity $activity -Status "Restoring crash dump policy"
Restore-BlackbirdCrashDumpSettings

Write-Stage -Index 6 -Total $totalStages -Activity $activity -Status "Removing firewall rules"
Remove-FirewallRuleIfPresent -DisplayName "Blackbird Operator UDP Discovery"
Remove-FirewallRuleIfPresent -DisplayName "Blackbird Operator TCP Status"
Remove-FirewallRuleIfPresent -DisplayName "Blackbird Operator TCP Command"
Remove-FirewallRuleIfPresent -DisplayName "Blackbird Operator ICMPv4"

Write-Stage -Index 7 -Total $totalStages -Activity $activity -Status "Removal complete"
Write-VerboseLog "Driver and controller teardown finished"

Write-Progress -Id 1 -Activity $activity -Completed
Write-Host "[*] Removed services and binaries for driver '$DriverName' and controller '$ControllerName'"

