param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$srcPath = Join-Path $repoRoot "user\hook_rs\src\lib.rs"
$outDir = Join-Path $repoRoot "x64\$Configuration"
$outDll = Join-Path $outDir "bkrs.dll"

if (!(Test-Path $outDir)) {
    New-Item -ItemType Directory -Path $outDir | Out-Null
}

$commonArgs = @(
    "--crate-type", "cdylib",
    "--edition=2021",
    $srcPath,
    "-o", $outDll
)

if ($Configuration -eq "Release") {
    $commonArgs += @(
        "-C", "panic=abort",
        "-C", "lto=fat",
        "-C", "codegen-units=1",
        "-C", "opt-level=z",
        "-C", "strip=symbols"
    )
} else {
    $commonArgs += @(
        "-C", "panic=abort",
        "-C", "debuginfo=2"
    )
}

& rustc @commonArgs
if ($LASTEXITCODE -ne 0) {
    throw "rustc failed with exit code $LASTEXITCODE"
}

Write-Host "Built $outDll"
