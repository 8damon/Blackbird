[CmdletBinding()]
param(
    [string]$OutputDirectory,
    [string]$ElectronRuntimeRoot,
    [switch]$AllowPartial,
    [switch]$RebuildElectronRuntime
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $repoRoot "x64\Release"
}
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$results = [Collections.Generic.List[object]]::new()

function Add-Result([string]$Name, [string]$Status, [string]$Detail, [string]$Path = "") {
    $results.Add([pscustomobject]@{ name = $Name; status = $Status; detail = $Detail; path = $Path })
    $color = if ($Status -eq "built") { "Green" } elseif ($Status -eq "skipped") { "Yellow" } else { "Red" }
    Write-Host ("[{0}] {1}: {2}" -f $Status.ToUpperInvariant(), $Name, $Detail) -ForegroundColor $color
}

function Find-VsDevCmd {
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path -LiteralPath $vswhere) {
        $installation = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
        if ($installation) {
            $candidate = Join-Path ($installation | Select-Object -First 1) "Common7\Tools\VsDevCmd.bat"
            if (Test-Path -LiteralPath $candidate) { return $candidate }
        }
    }
    foreach ($candidate in @(
        "C:\Program Files\Microsoft Visual Studio\18\Insiders\Common7\Tools\VsDevCmd.bat",
        "C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\VsDevCmd.bat",
        "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat",
        "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat"
    )) {
        if (Test-Path -LiteralPath $candidate) { return $candidate }
    }
    return $null
}

function Invoke-VcBuild([string]$Name, [string]$Source, [string]$Output, [string]$ExtraFlags) {
    $dev = Find-VsDevCmd
    if (-not $dev) { Add-Result $Name "missing" "MSVC x64 tools were not found"; return $false }
    $command = 'call "{0}" -arch=x64 -host_arch=x64 >nul && cl /nologo /O2 /W4 "{1}" /Fe:"{2}" {3}' -f $dev, $Source, $Output, $ExtraFlags
    & cmd.exe /d /s /c $command
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $Output)) {
        Add-Result $Name "failed" "cl.exe returned $LASTEXITCODE"
        return $false
    }
    Add-Result $Name "built" "MSVC release build" $Output
    return $true
}

Invoke-VcBuild "benign_c_native" (Join-Path $repoRoot "benign_apps\c\normal_native.c") `
    (Join-Path $OutputDirectory "bb_ok_c_native.exe") "advapi32.lib" | Out-Null
Invoke-VcBuild "benign_cpp_ui" (Join-Path $repoRoot "benign_apps\cpp_ui\normal_ui.cpp") `
    (Join-Path $OutputDirectory "bb_ok_cpp_ui.exe") "/EHsc /link /SUBSYSTEM:WINDOWS user32.lib gdi32.lib" | Out-Null
Invoke-VcBuild "benign_electron_launcher" (Join-Path $repoRoot "benign_apps\electron_ui\launcher.c") `
    (Join-Path $OutputDirectory "bb_ok_electron_launcher.exe") "" | Out-Null

$go = Get-Command go -ErrorAction SilentlyContinue | Select-Object -First 1
if ($go) {
    $previousCgo = $env:CGO_ENABLED
    try {
        $env:CGO_ENABLED = "0"
        Push-Location (Join-Path $repoRoot "benign_apps\go_worker")
        & $go.Source build -trimpath -ldflags "-s -w" -o (Join-Path $OutputDirectory "bb_ok_go_worker.exe") .
        if ($LASTEXITCODE -ne 0) { throw "go build returned $LASTEXITCODE" }
        Add-Result "benign_go_worker" "built" (& $go.Source version) (Join-Path $OutputDirectory "bb_ok_go_worker.exe")
    } catch { Add-Result "benign_go_worker" "failed" $_.Exception.Message }
    finally { Pop-Location; $env:CGO_ENABLED = $previousCgo }
} else { Add-Result "benign_go_worker" "missing" "Go toolchain was not found" }

$cargo = Get-Command cargo -ErrorAction SilentlyContinue | Select-Object -First 1
function Invoke-CargoBuild([string]$Name, [string]$Project, [string]$Binary) {
    if (-not $cargo) { Add-Result $Name "missing" "Cargo was not found"; return }
    try {
        $arguments = @("build", "--manifest-path", (Join-Path $Project "Cargo.toml"), "--release", "--offline")
        if (Test-Path -LiteralPath (Join-Path $Project "Cargo.lock")) { $arguments += "--locked" }
        & $cargo.Source @arguments
        if ($LASTEXITCODE -ne 0) { throw "cargo build returned $LASTEXITCODE" }
        $source = Join-Path $Project "target\release\$Binary.exe"
        $destination = Join-Path $OutputDirectory "$Binary.exe"
        Copy-Item -LiteralPath $source -Destination $destination -Force
        Add-Result $Name "built" "Cargo locked offline release build" $destination
    } catch { Add-Result $Name "failed" $_.Exception.Message }
}
Invoke-CargoBuild "benign_rust_native" (Join-Path $repoRoot "benign_apps\rust_native") "bb_ok_rust_native"
Invoke-CargoBuild "benign_rust_axum_ui" (Join-Path $repoRoot "benign_apps\rust_axum_ui") "bb_ok_rust_axum_ui"
Invoke-CargoBuild "benign_tauri_ui" (Join-Path $repoRoot "benign_apps\tauri_ui\src-tauri") "bb_ok_tauri_ui"

if ([string]::IsNullOrWhiteSpace($ElectronRuntimeRoot)) {
    $profileCandidates = @()
    $profilesRoot = Join-Path $env:SystemDrive "Users"
    if (Test-Path -LiteralPath $profilesRoot) {
        $profileCandidates = @(Get-ChildItem -LiteralPath $profilesRoot -Directory -Force -ErrorAction SilentlyContinue |
            ForEach-Object { Join-Path $_.FullName "AppData\Local\Programs\Microsoft VS Code" })
    }
    $candidates = @(
        "$env:LOCALAPPDATA\Programs\Microsoft VS Code",
        "$env:LOCALAPPDATA\AMD\AI_Bundle\VSCode"
    ) + $profileCandidates
    $ElectronRuntimeRoot = $candidates | Where-Object { Test-Path -LiteralPath (Join-Path $_ "Code.exe") } | Select-Object -First 1
}
$electronOutput = Join-Path $OutputDirectory "benign_electron"
if ($ElectronRuntimeRoot -and (Test-Path -LiteralPath (Join-Path $ElectronRuntimeRoot "Code.exe"))) {
    try {
        if (Test-Path -LiteralPath $electronOutput) {
            if (-not $RebuildElectronRuntime) { throw "output already exists; use -RebuildElectronRuntime" }
            $resolved = [IO.Path]::GetFullPath($electronOutput)
            if (-not $resolved.StartsWith($OutputDirectory, [StringComparison]::OrdinalIgnoreCase)) { throw "unsafe output path" }
            if ((Get-Item -LiteralPath $electronOutput -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "output is a reparse point" }
            Remove-Item -LiteralPath $electronOutput -Recurse -Force
        }
        New-Item -ItemType Directory -Path $electronOutput | Out-Null
        & robocopy.exe $ElectronRuntimeRoot $electronOutput /E /XD (Join-Path $ElectronRuntimeRoot "resources\app") /R:1 /W:1 /NFL /NDL /NJH /NJS /NP
        if ($LASTEXITCODE -gt 7) { throw "robocopy returned $LASTEXITCODE" }
        $appOutput = Join-Path $electronOutput "resources\app"
        New-Item -ItemType Directory -Force -Path $appOutput | Out-Null
        Copy-Item -LiteralPath (Join-Path $repoRoot "benign_apps\electron_ui\package.json"), `
            (Join-Path $repoRoot "benign_apps\electron_ui\main.js"), `
            (Join-Path $repoRoot "benign_apps\electron_ui\preload.js"), `
            (Join-Path $repoRoot "benign_apps\electron_ui\index.html") -Destination $appOutput
        Rename-Item -LiteralPath (Join-Path $electronOutput "Code.exe") -NewName "BlackbirdBenignElectron.exe"
        Add-Result "benign_electron_ui" "built" "packaged from the installed Electron runtime" `
            (Join-Path $electronOutput "BlackbirdBenignElectron.exe")
    } catch { Add-Result "benign_electron_ui" "failed" $_.Exception.Message }
} else { Add-Result "benign_electron_ui" "missing" "an installed Electron/VS Code runtime was not found" }

$manifestPath = Join-Path $OutputDirectory "benign-apps-build.json"
[pscustomobject]@{
    schema = 1
    generatedUtc = [DateTime]::UtcNow.ToString("o")
    computer = $env:COMPUTERNAME
    outputDirectory = $OutputDirectory
    results = $results
} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $manifestPath -Encoding utf8

$failures = @($results | Where-Object status -in @("failed", "missing"))
if ($failures.Count -gt 0 -and -not $AllowPartial) {
    throw "Benign application build incomplete: $($failures.name -join ', ')"
}
Write-Host "Build record: $manifestPath"
