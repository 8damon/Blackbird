param(
    [string]$OutDir = "",
    [ValidateSet("all", "apc", "beacon", "benign", "hollowing", "injection", "kerberos", "loader", "lotl", "lpe", "mem", "network", "process", "registry", "service", "sxs", "syscall")]
    [string[]]$Category = @("all"),
    [string]$Configuration = "Release",
    [ValidateSet("x64", "x86", "Win32")]
    [string]$Platform = "x64",
    [ValidateSet("Auto", "On", "Off")]
    [string]$ControlFlowGuard = "Auto",
    [ValidateSet("Default", "Native", "AVX2")]
    [string]$InstructionSet = "Native",
    [switch]$Clean,
    [switch]$CleanOnly,
    [string]$ManifestPath = "",
    [switch]$SkipManifest,
    [switch]$GenerateManifestOnly
)

$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path -LiteralPath $PSScriptRoot).Path
$platformOut = if ($Platform -ieq "Win32" -or $Platform -ieq "x86") { "x86" } else { "x64" }
if ([string]::IsNullOrWhiteSpace($OutDir)) {
    $OutDir = Join-Path $repoRoot "$platformOut\$Configuration"
}
if ([string]::IsNullOrWhiteSpace($ManifestPath)) {
    $ManifestPath = Join-Path $repoRoot "manifests\aes.samples.generated.json"
}
elseif (-not [System.IO.Path]::IsPathRooted($ManifestPath)) {
    $ManifestPath = Join-Path $repoRoot $ManifestPath
}
if ($GenerateManifestOnly -and $SkipManifest) {
    throw "-GenerateManifestOnly cannot be combined with -SkipManifest."
}

function Enter-MsvcEnvironment {
    $includeReady = -not [string]::IsNullOrWhiteSpace($env:INCLUDE) -and $env:INCLUDE -match "Windows Kits"
    if ((Get-Command cl.exe -ErrorAction SilentlyContinue) -and $includeReady) {
        return
    }

    if ($env:BKAES_VSDEV_REENTERED -eq "1") {
        throw "MSVC was found but the Windows SDK include environment is still unavailable."
    }

    $vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
    if (-not (Test-Path -LiteralPath $vswhere)) {
        throw "cl.exe/Windows SDK environment is not ready, and vswhere.exe was not found. Run from an x64 MSVC Developer PowerShell."
    }

    $installPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    $devCmd = $null
    if (-not [string]::IsNullOrWhiteSpace($installPath)) {
        $devCmd = Join-Path $installPath "Common7\Tools\VsDevCmd.bat"
    }
    if ([string]::IsNullOrWhiteSpace($devCmd) -or -not (Test-Path -LiteralPath $devCmd)) {
        $devCmd = Get-ChildItem -Path "$env:ProgramFiles\Microsoft Visual Studio" -Recurse -Filter VsDevCmd.bat -ErrorAction SilentlyContinue |
            Select-Object -First 1 -ExpandProperty FullName
    }
    if (-not (Test-Path -LiteralPath $devCmd)) {
        throw "VsDevCmd.bat was not found at $devCmd"
    }

    $arch = if ($platformOut -eq "x86") { "x86" } else { "x64" }
    $categoryArgs = ($Category | ForEach-Object { " -Category `"$($_)`"" }) -join ""
    $cleanArg = if ($Clean) { " -Clean" } else { "" }
    $cleanOnlyArg = if ($CleanOnly) { " -CleanOnly" } else { "" }
    $manifestArg = " -ManifestPath `"$ManifestPath`""
    $skipManifestArg = if ($SkipManifest -or -not $GenerateManifestOnly) { " -SkipManifest" } else { "" }
    $generateManifestOnlyArg = if ($GenerateManifestOnly) { " -GenerateManifestOnly" } else { "" }
    $cmd = "`"$devCmd`" -arch=$arch -host_arch=x64 && set BKAES_VSDEV_REENTERED=1 && powershell -NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -OutDir `"$OutDir`"$categoryArgs -Configuration `"$Configuration`" -Platform `"$Platform`" -ControlFlowGuard $ControlFlowGuard -InstructionSet $InstructionSet$cleanArg$cleanOnlyArg$manifestArg$skipManifestArg$generateManifestOnlyArg"
    & cmd.exe /d /s /c $cmd
    exit $LASTEXITCODE
}

function Get-ObjectPath {
    param([string]$SourcePath)

    $full = (Resolve-Path -LiteralPath $SourcePath).Path
    $prefix = $repoRoot.TrimEnd("\") + "\"
    if ($full.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        $relative = $full.Substring($prefix.Length)
    }
    else {
        $relative = Split-Path -Leaf $full
    }

    $safe = [regex]::Replace($relative, "[^A-Za-z0-9_]+", "_")
    return Join-Path $objDir "$safe.obj"
}

function Compile-Object {
    param([string]$SourcePath)

    $objectPath = Get-ObjectPath $SourcePath
    Write-Host "[BKAES] obj $(Split-Path -Leaf $SourcePath)"
    & cl.exe @compileArgs /c $SourcePath "/Fo$objectPath" | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "cl.exe failed for $SourcePath"
    }
    return $objectPath
}

function Get-BuildOutputName {
    param([hashtable]$Build)

    if ($Build.ContainsKey("OutputName") -and -not [string]::IsNullOrWhiteSpace($Build.OutputName)) {
        return $Build.OutputName
    }
    return "$($Build.Name).exe"
}

function Remove-GeneratedOutputs {
    param(
        [hashtable[]]$Builds,
        [bool]$IncludePlugin
    )

    if (-not (Test-Path -LiteralPath $OutDir)) {
        return
    }

    $names = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($build in $Builds) {
        [void]$names.Add((Get-BuildOutputName $build))
        [void]$names.Add("$($build.Name).pdb")
        [void]$names.Add("$($build.Name).ilk")
    }
    if ($IncludePlugin) {
        foreach ($name in @(
                "bb_unsigned_plugin.dll",
                "bb_unsigned_plugin.pdb",
                "bb_unsigned_plugin.exp",
                "bb_unsigned_plugin.lib",
                "version.dll",
                "version.pdb",
                "invoice.pdf.dll",
                "invoice.pdf.pdb",
                "invoice.pdf.exe",
                "invoice.pdf.ilk",
                "invoice.pdf.pdb"
            )) {
            [void]$names.Add($name)
        }
    }

    foreach ($name in $names) {
        $path = Join-Path $OutDir $name
        if (Test-Path -LiteralPath $path) {
            Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
        }
    }
    if (Test-Path -LiteralPath $objDir) {
        Remove-Item -LiteralPath $objDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Resolve-ControlFlowGuard {
    param([string]$CategoryName)

    if ($ControlFlowGuard -eq "On") {
        return $true
    }
    if ($ControlFlowGuard -eq "Off") {
        return $false
    }

    return $CategoryName -notin @("apc", "hollowing", "injection", "loader", "mem", "syscall")
}

function Build-Exe {
    param(
        [string]$Name,
        [string]$Define,
        [string]$CategoryName,
        [string]$OutputName = $null
    )

    if ([string]::IsNullOrWhiteSpace($OutputName)) {
        $OutputName = "$Name.exe"
    }

    $driverObj = Join-Path $objDir "$Name.driver.obj"
    $outPath = Join-Path $OutDir $OutputName

    Write-Host "[BKAES] exe $OutputName"
    & cl.exe @compileArgs "/D$Define" /c $driver "/Fo$driverObj"
    if ($LASTEXITCODE -ne 0) {
        throw "cl.exe failed for dispatcher $Name"
    }

    $guardArgs = if (Resolve-ControlFlowGuard $CategoryName) { @("/GUARD:CF") } else { @("/GUARD:NO") }
    $linkArgs = @("/nologo") + $guardArgs + @("/OUT:$outPath", "/SUBSYSTEM:CONSOLE", $driverObj) + $objectPaths + $linkLibs
    $linkArgs = @($linkArgs | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    & link.exe @linkArgs
    if ($LASTEXITCODE -ne 0) {
        throw "link.exe failed for $Name"
    }

}

function Build-Dll {
    param([string]$OutputName)

    $outPath = Join-Path $OutDir $OutputName
    $objectPath = Join-Path $objDir "bkaes_unsigned_plugin.obj"
    $importLib = Join-Path $objDir "bkaes_unsigned_plugin.lib"

    Write-Host "[BKAES] dll $OutputName"
    & cl.exe @compileArgs /c $plugin "/Fo$objectPath"
    if ($LASTEXITCODE -ne 0) {
        throw "cl.exe failed for $OutputName"
    }

    $linkArgs = @("/nologo", "/DLL", "/GUARD:NO", "/OUT:$outPath", "/IMPLIB:$importLib", $objectPath,
        "advapi32.lib", "user32.lib")
    & link.exe @linkArgs
    if ($LASTEXITCODE -ne 0) {
        throw "link.exe failed for $OutputName"
    }
}

function Invoke-WithPluginBuildLock {
    param([scriptblock]$Action)

    $sha = [System.Security.Cryptography.SHA256]::Create()
    $bytes = [System.Text.Encoding]::Unicode.GetBytes($OutDir.ToLowerInvariant())
    $hash = [System.BitConverter]::ToString($sha.ComputeHash($bytes)).Replace("-", "").Substring(0, 16)
    $mutex = New-Object System.Threading.Mutex($false, "BKAES_PLUGIN_$hash")
    $acquired = $false
    try {
        $acquired = $mutex.WaitOne([TimeSpan]::FromMinutes(5))
        if (-not $acquired) {
            throw "Timed out waiting for plugin build lock."
        }
        & $Action
    }
    finally {
        if ($acquired) {
            $mutex.ReleaseMutex()
        }
        $mutex.Dispose()
        $sha.Dispose()
    }
}

function Get-SampleId {
    param([hashtable]$Build)

    return ($Build["Name"] -replace "^bb_(det|ok|fuzz)_", "")
}

function Get-SampleKind {
    param([hashtable]$Build)

    $name = $Build["Name"]
    if ($name.StartsWith("bb_ok_", [System.StringComparison]::OrdinalIgnoreCase)) {
        return "benign"
    }
    if ($name.StartsWith("bb_fuzz_", [System.StringComparison]::OrdinalIgnoreCase)) {
        return "fuzzer"
    }
    if ($name -eq "bb_det_sensitive_credential_handles") {
        return "detection-sensitive"
    }
    return "detection"
}

function Get-SampleArguments {
    param([hashtable]$Build)

    if ($Build["Name"] -eq "bb_det_sensitive_credential_handles") {
        return @("--enable-sensitive")
    }
    return @()
}

function Get-FullPath {
    param([string]$Path)

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return [System.IO.Path]::GetFullPath($Path)
    }
    return [System.IO.Path]::GetFullPath((Join-Path (Get-Location).Path $Path))
}

function Get-RelativePathFromDirectory {
    param(
        [string]$FromDirectory,
        [string]$ToPath
    )

    $from = [System.IO.Path]::GetFullPath($FromDirectory)
    if (-not $from.EndsWith([System.IO.Path]::DirectorySeparatorChar)) {
        $from += [System.IO.Path]::DirectorySeparatorChar
    }
    $to = [System.IO.Path]::GetFullPath($ToPath)
    $fromUri = [Uri]$from
    $toUri = [Uri]$to
    if ($fromUri.Scheme -ne $toUri.Scheme) {
        return $to
    }
    $relativeUri = $fromUri.MakeRelativeUri($toUri)
    return [Uri]::UnescapeDataString($relativeUri.ToString()).Replace("/", [System.IO.Path]::DirectorySeparatorChar)
}

function Write-GeneratedSampleManifest {
    param([hashtable[]]$Builds)

    $manifestDir = Split-Path -Parent $ManifestPath
    New-Item -ItemType Directory -Force -Path $manifestDir | Out-Null

    $outDirFull = Get-FullPath $OutDir
    $samples = foreach ($build in ($Builds | Sort-Object { $_["Category"] }, { $_["Name"] })) {
        $outputPath = Join-Path $outDirFull (Get-BuildOutputName $build)
        $binaryPath = Get-RelativePathFromDirectory -FromDirectory $manifestDir -ToPath $outputPath
        $sample = [ordered]@{
            id       = Get-SampleId $build
            category = $build["Category"]
            kind     = Get-SampleKind $build
            binary   = $binaryPath.Replace("\", "/")
            define   = $build["Define"]
        }
        $arguments = @(Get-SampleArguments $build)
        if ($arguments.Count -gt 0) {
            $sample["arguments"] = $arguments
        }
        [pscustomobject]$sample
    }

    $manifest = [ordered]@{
        schema             = 1
        suite              = "Blackbird Adversary Emulation Suite"
        generated_at_utc   = (Get-Date).ToUniversalTime().ToString("o")
        output_platform    = $platformOut
        output_configuration = $Configuration
        safety_model       = "DSGL-only Blackbird capability test samples. Generated binaries are not redistributable."
        samples            = @($samples)
    }

    $sha = [System.Security.Cryptography.SHA256]::Create()
    $hashBytes = [System.Text.Encoding]::Unicode.GetBytes($ManifestPath.ToLowerInvariant())
    $hash = [System.BitConverter]::ToString($sha.ComputeHash($hashBytes)).Replace("-", "").Substring(0, 16)
    $mutex = New-Object System.Threading.Mutex($false, "BKAES_MANIFEST_$hash")
    $acquired = $false
    $tempPath = "$ManifestPath.$PID.tmp"
    try {
        $acquired = $mutex.WaitOne([TimeSpan]::FromMinutes(2))
        if (-not $acquired) {
            throw "Timed out waiting for manifest generation lock."
        }

        $json = ($manifest | ConvertTo-Json -Depth 8)
        $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($tempPath, $json + [Environment]::NewLine, $utf8NoBom)
        Move-Item -LiteralPath $tempPath -Destination $ManifestPath -Force
    }
    finally {
        if (Test-Path -LiteralPath $tempPath) {
            Remove-Item -LiteralPath $tempPath -Force
        }
        if ($acquired) {
            $mutex.ReleaseMutex()
        }
        $mutex.Dispose()
        $sha.Dispose()
    }
    Write-Host "[BKAES] generated sample manifest $ManifestPath"
}

$OutDir = Get-FullPath $OutDir
$baseObjDir = Join-Path $OutDir "obj\bkaes"

$commonDir = Join-Path $repoRoot "common"
$driver = Join-Path $commonDir "bkaes_sample_dispatch.cpp"
$plugin = Join-Path $repoRoot "sxs\bkaes_unsigned_plugin.cpp"

$allCategories = @("apc", "beacon", "benign", "hollowing", "injection", "kerberos", "loader", "lotl", "lpe", "mem", "network", "process", "registry", "service", "sxs", "syscall")
$requestedCategories = @($Category | ForEach-Object { $_.ToLowerInvariant() })
$selectedCategories = if ($requestedCategories -contains "all") {
    $allCategories
}
else {
    @($requestedCategories | Sort-Object -Unique)
}
if ($platformOut -ne "x64" -and $selectedCategories -contains "loader") {
    throw "The loader fixtures require Platform x64."
}

$selectedCategorySet = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)
foreach ($categoryName in $selectedCategories) {
    [void]$selectedCategorySet.Add($categoryName)
}
$objDir = Join-Path $baseObjDir ($selectedCategories -join "_")

$sampleBuilds = @(
    @{ Category = "syscall"; Name = "bb_det_direct_syscall_handle"; Define = "BKAES_SAMPLE_DIRECT_SYSCALL_HANDLE" },
    @{ Category = "syscall"; Name = "bb_det_direct_syscall_stack_tf"; Define = "BKAES_SAMPLE_DIRECT_SYSCALL_STACK_TF" },
    @{ Category = "syscall"; Name = "bb_det_nt_stub_integrity_check"; Define = "BKAES_SAMPLE_NT_STUB_INTEGRITY_CHECK" },
    @{ Category = "syscall"; Name = "bb_det_anti_debug_vm_queries"; Define = "BKAES_SAMPLE_ANTI_DEBUG_VM_QUERIES" },
    @{ Category = "syscall"; Name = "bb_fuzz_ntapi_queries"; Define = "BKAES_SAMPLE_FUZZ_NTAPI_QUERIES" },
    @{ Category = "injection"; Name = "bb_det_injection_chain_complete"; Define = "BKAES_SAMPLE_INJECTION_CHAIN_COMPLETE" },
    @{ Category = "injection"; Name = "bb_det_pe_injection_write"; Define = "BKAES_SAMPLE_PE_INJECTION_WRITE" },
    @{ Category = "injection"; Name = "bb_det_section_map_execute"; Define = "BKAES_SAMPLE_SECTION_MAP_EXECUTE" },
    @{ Category = "injection"; Name = "bb_det_remote_apc_loadlibrary"; Define = "BKAES_SAMPLE_REMOTE_APC_LOADLIBRARY" },
    @{ Category = "injection"; Name = "bb_det_context_hijack_tf"; Define = "BKAES_SAMPLE_CONTEXT_HIJACK_TF" },
    @{ Category = "injection"; Name = "bb_det_loadlibrary_remote_thread"; Define = "BKAES_SAMPLE_LOADLIBRARY_REMOTE_THREAD" },
    @{ Category = "injection"; Name = "bb_det_direct_syscall_injection_chain"; Define = "BKAES_SAMPLE_DIRECT_SYSCALL_INJECTION_CHAIN" },
    @{ Category = "injection"; Name = "bb_det_wow64_injection_chain"; Define = "BKAES_SAMPLE_WOW64_INJECTION_CHAIN" },
    @{ Category = "injection"; Name = "bb_det_evasion_injection_chain"; Define = "BKAES_SAMPLE_EVASION_INJECTION_CHAIN" },
    @{ Category = "injection"; Name = "bb_det_loadlibrary_module_notify"; Define = "BKAES_SAMPLE_LOADLIBRARY_MODULE_NOTIFY" },
    @{ Category = "injection"; Name = "bb_det_setwindows_hookex"; Define = "BKAES_SAMPLE_SETWINDOWS_HOOKEX" },
    @{ Category = "injection"; Name = "bb_det_setwinevent_hook"; Define = "BKAES_SAMPLE_SETWINEVENT_HOOK" },
    @{ Category = "injection"; Name = "bb_ok_gui_hook_target"; Define = "BKAES_SAMPLE_GUI_HOOK_TARGET" },
    @{ Category = "hollowing"; Name = "bb_det_hollowing_mark_chain"; Define = "BKAES_SAMPLE_HOLLOWING_MARK_CHAIN" },
    @{ Category = "hollowing"; Name = "bb_det_transacted_hollowing_marker"; Define = "BKAES_SAMPLE_TRANSACTED_HOLLOWING_MARKER" },
    @{ Category = "apc"; Name = "bb_det_remote_apc_queue"; Define = "BKAES_SAMPLE_REMOTE_APC_QUEUE" },
    @{ Category = "apc"; Name = "bb_det_early_bird_apc"; Define = "BKAES_SAMPLE_EARLY_BIRD_APC" },
    @{ Category = "process"; Name = "bb_det_ppid_spoof"; Define = "BKAES_SAMPLE_PPID_SPOOF" },
    @{ Category = "process"; Name = "bb_det_target_nonzero_exit"; Define = "BKAES_SAMPLE_TARGET_NONZERO_EXIT" },
    @{ Category = "process"; Name = "bb_det_target_exception"; Define = "BKAES_SAMPLE_TARGET_EXCEPTION" },
    @{ Category = "lotl"; Name = "bb_det_powershell_cmdlines"; Define = "BKAES_SAMPLE_POWERSHELL_CMDLINES" },
    @{ Category = "lotl"; Name = "bb_det_lolbin_cmdlines"; Define = "BKAES_SAMPLE_LOLBIN_CMDLINES" },
    @{ Category = "registry"; Name = "bb_det_registry_persistence_hkcu"; Define = "BKAES_SAMPLE_REGISTRY_PERSISTENCE_HKCU" },
    @{ Category = "registry"; Name = "bb_det_registry_recon"; Define = "BKAES_SAMPLE_REGISTRY_RECON" },
    @{ Category = "registry"; Name = "bb_fuzz_registry_paths"; Define = "BKAES_SAMPLE_FUZZ_REGISTRY_PATHS" },
    @{ Category = "service"; Name = "bb_det_edr_av_product_probes"; Define = "BKAES_SAMPLE_EDR_AV_PRODUCT_PROBES" },
    @{ Category = "service"; Name = "bb_det_security_product_enterprise_geo_probes"; Define = "BKAES_SAMPLE_SECURITY_PRODUCT_ENTERPRISE_GEO_PROBES" },
    @{ Category = "service"; Name = "bb_det_com_wmi_etw_job"; Define = "BKAES_SAMPLE_COM_WMI_ETW_JOB" },
    @{ Category = "sxs"; Name = "bb_det_dll_load_surface"; Define = "BKAES_SAMPLE_DLL_LOAD_SURFACE" },
    @{ Category = "sxs"; Name = "bb_det_image_load_double_extension"; Define = "BKAES_SAMPLE_IMAGE_LOAD_DOUBLE_EXTENSION"; OutputName = "invoice.pdf.exe" },
    @{ Category = "sxs"; Name = "bb_fuzz_module_loads"; Define = "BKAES_SAMPLE_FUZZ_MODULE_LOADS" },
    @{ Category = "sxs"; Name = "bb_ok_system_dll_loads"; Define = "BKAES_SAMPLE_OK_SYSTEM_DLL_LOADS" },
    @{ Category = "mem"; Name = "bb_det_dynamic_function_table"; Define = "BKAES_SAMPLE_DYNAMIC_FUNCTION_TABLE" },
    @{ Category = "mem"; Name = "bb_det_memory_flips_entropy"; Define = "BKAES_SAMPLE_MEMORY_FLIPS_ENTROPY" },
    @{ Category = "mem"; Name = "bb_det_guard_ordered_jit"; Define = "BKAES_SAMPLE_GUARD_ORDERED_JIT" },
    @{ Category = "mem"; Name = "bb_det_xor_entropy_cycle"; Define = "BKAES_SAMPLE_XOR_ENTROPY_CYCLE" },
    @{ Category = "mem"; Name = "bb_ok_memory_process"; Define = "BKAES_SAMPLE_OK_MEMORY_PROCESS" },
    @{ Category = "network"; Name = "bb_det_network_patterns"; Define = "BKAES_SAMPLE_NETWORK_PATTERNS" },
    @{ Category = "network"; Name = "bb_ok_network_loopback"; Define = "BKAES_SAMPLE_OK_NETWORK_LOOPBACK" },
    @{ Category = "network"; Name = "bb_ok_localhost_service"; Define = "BKAES_SAMPLE_OK_LOCALHOST_SERVICE" },
    @{ Category = "beacon"; Name = "bb_det_beacon_loopback_pattern"; Define = "BKAES_SAMPLE_BEACON_LOOPBACK_PATTERN" },
    @{ Category = "kerberos"; Name = "bb_det_sensitive_credential_handles"; Define = "BKAES_SAMPLE_SENSITIVE_CREDENTIAL_HANDLES" },
    @{ Category = "kerberos"; Name = "bb_det_kerberos_recon_extended"; Define = "BKAES_SAMPLE_KERBEROS_RECON_EXTENDED" },
    @{ Category = "lpe"; Name = "bb_det_lpe_surface"; Define = "BKAES_SAMPLE_LPE_SURFACE" },
    @{ Category = "benign"; Name = "bb_ok_file_registry"; Define = "BKAES_SAMPLE_OK_FILE_REGISTRY" },
    @{ Category = "benign"; Name = "bb_ok_document_workflow"; Define = "BKAES_SAMPLE_OK_DOCUMENT_WORKFLOW" },
    @{ Category = "benign"; Name = "bb_ok_system_inventory"; Define = "BKAES_SAMPLE_OK_SYSTEM_INVENTORY" },
    @{ Category = "benign"; Name = "bb_ok_com_logging_job"; Define = "BKAES_SAMPLE_OK_COM_LOGGING_JOB" }
)
$selectedBuilds = @($sampleBuilds | Where-Object { $selectedCategorySet.Contains($_["Category"]) })
if ($selectedBuilds.Count -eq 0) {
    throw "No AES samples selected for category '$($Category -join ",")'."
}

if ($GenerateManifestOnly) {
    Write-GeneratedSampleManifest -Builds $sampleBuilds
    exit 0
}
if (-not $SkipManifest -and -not $CleanOnly) {
    Write-GeneratedSampleManifest -Builds $sampleBuilds
}

$needsPlugin = $selectedCategorySet.Contains("injection") -or $selectedCategorySet.Contains("sxs")
if ($Clean -or $CleanOnly) {
    Remove-GeneratedOutputs -Builds $selectedBuilds -IncludePlugin $needsPlugin
}
if ($CleanOnly) {
    Write-Host "[BKAES] cleaned samples in $OutDir"
    exit 0
}

Enter-MsvcEnvironment

$sampleSources = foreach ($folder in $selectedCategories) {
    $path = Join-Path $repoRoot $folder
    if (Test-Path -LiteralPath $path) {
        Get-ChildItem -LiteralPath $path -Filter "*.cpp" -File |
            Where-Object { $_.Name -ne "bkaes_unsigned_plugin.cpp" } |
            Sort-Object FullName |
            ForEach-Object { $_.FullName }
    }
}

$supportSources = @(
    (Join-Path $commonDir "bkaes_common.cpp"),
    (Join-Path $commonDir "bkaes_sample_support.cpp")
)
$extraSources = @()
if ($selectedCategorySet.Contains("service")) {
    $extraSources += Join-Path $repoRoot "lotl\cmdline_helpers.cpp"
}
$objectSources = @($supportSources + $sampleSources + $extraSources) | Select-Object -Unique

$compileArgs = @(
    "/nologo",
    "/MP",
    "/std:c++20",
    "/EHsc",
    "/W3",
    "/DUNICODE",
    "/D_UNICODE",
    "/DWIN32_LEAN_AND_MEAN",
    "/I$commonDir"
)
if ($Configuration -ieq "Debug") {
    $compileArgs += @("/Od", "/Zi", "/D_DEBUG")
}
else {
    $compileArgs += @("/O2", "/DNDEBUG")
}
if (($InstructionSet -eq "Native" -or $InstructionSet -eq "AVX2") -and ($platformOut -eq "x64" -or $platformOut -eq "x86")) {
    $compileArgs += "/arch:AVX2"
}
if ($ControlFlowGuard -eq "On" -or ($ControlFlowGuard -eq "Auto" -and @($selectedCategories | Where-Object { Resolve-ControlFlowGuard $_ }).Count -gt 0)) {
    $compileArgs += "/guard:cf"
}
$linkLibs = @("advapi32.lib", "iphlpapi.lib", "ole32.lib", "wbemuuid.lib", "ws2_32.lib", "secur32.lib", "user32.lib")
New-Item -ItemType Directory -Force -Path $objDir | Out-Null

$objectPaths = foreach ($sourcePath in $objectSources) {
    Compile-Object $sourcePath
}

if ($needsPlugin) {
    Invoke-WithPluginBuildLock {
        Build-Dll "bb_unsigned_plugin.dll"
        Copy-Item -LiteralPath (Join-Path $OutDir "bb_unsigned_plugin.dll") -Destination (Join-Path $OutDir "version.dll") -Force
        Copy-Item -LiteralPath (Join-Path $OutDir "bb_unsigned_plugin.dll") -Destination (Join-Path $OutDir "invoice.pdf.dll") -Force
    }
}

foreach ($build in $selectedBuilds) {
    $outputName = if ($build.ContainsKey("OutputName")) { $build["OutputName"] } else { $null }
    Build-Exe -Name $build["Name"] -Define $build["Define"] -CategoryName $build["Category"] -OutputName $outputName
}

Remove-Item -LiteralPath $objDir -Recurse -Force
Write-Host "[BKAES] built $($selectedBuilds.Count) sample(s) for $($selectedCategories -join ",") in $OutDir"
