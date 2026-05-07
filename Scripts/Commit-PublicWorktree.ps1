param(
    [switch] $PlanOnly,
    [switch] $Force
)

$ErrorActionPreference = 'Stop'

$repoRoot = (& git rev-parse --show-toplevel).Trim()
if (-not $repoRoot) {
    throw 'This script must be run from inside the Blackbird git repository.'
}

Set-Location $repoRoot

$privateOrExternalPaths = @(
    'Blackbird.code-workspace',
    'Client/analysis/Rules/SignatureIntel/signature-rules.json',
    'Client/analysis/Rules/SignatureIntel/default-sigma.yml',
    'Client/analysis/Rules/SignatureIntel/Bundled/',
    'Docs/',
    'docs/',
    'Yara/',
    'Server/',
    'Lib/NetworkServiceLayer/',
    'Kernel/network/',
    'Kernel/core/crashdump.c',
    'Kernel/monitors/bugcheck_monitor.c',
    'Kernel/monitors/bugcheck_monitor.h',
    'Client/analysis/Services/OperatorIdentityService.cs',
    'Client/analysis/Services/VmRegistrationPackageService.cs',
    'Client/analysis/Windows/VmRegistrationWindow.xaml',
    'Client/analysis/Windows/VmRegistrationWindow.xaml.cs',
    'Scripts/Register-BlackbirdVm.ps1',
    'UserMode/controller/core/runtime/ns/ns_launcher.cpp',
    'UserMode/netsvc/',
    'Usermode/netsvc/',
    'VCXProj/BlackbirdNetSvc.vcxproj',
    'VCXProj/BlackbirdNetSvc.vcxproj.filters'
)

function Convert-ToGitPath {
    param([string] $Path)
    return ($Path -replace '\\', '/').TrimStart('./')
}

function Test-SkippedPath {
    param([string] $Path)

    $gitPath = Convert-ToGitPath $Path
    foreach ($skipPath in $privateOrExternalPaths) {
        $skip = Convert-ToGitPath $skipPath
        if ($skip.EndsWith('/')) {
            if ($gitPath.StartsWith($skip, [System.StringComparison]::OrdinalIgnoreCase)) {
                return $true
            }
        } elseif ($gitPath.Equals($skip, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }

    return $false
}

function Test-TrackedPath {
    param([string] $Path)

    $gitPath = Convert-ToGitPath $Path
    $tracked = @(& git ls-files -- $Path 2>$null | ForEach-Object { Convert-ToGitPath $_ })

    if ($gitPath.EndsWith('/')) {
        $prefix = $gitPath
    } else {
        $prefix = "$gitPath/"
    }

    foreach ($trackedPath in $tracked) {
        if ($trackedPath -ceq $gitPath) {
            return $true
        }

        if ($trackedPath.StartsWith($prefix, [System.StringComparison]::Ordinal)) {
            return $true
        }
    }

    return $false
}

function Test-ExactExistingPath {
    param([string] $Path)

    $requestedGitPath = Convert-ToGitPath $Path
    if ([string]::IsNullOrWhiteSpace($requestedGitPath)) {
        return $false
    }

    $current = $repoRoot
    foreach ($segment in $requestedGitPath.Split('/')) {
        if ([string]::IsNullOrWhiteSpace($segment)) {
            continue
        }

        $match = Get-ChildItem -LiteralPath $current -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -ceq $segment } |
            Select-Object -First 1

        if ($null -eq $match) {
            return $false
        }

        $current = $match.FullName
    }

    return $true
}

function Get-StageablePaths {
    param([string[]] $Paths)

    $stageable = New-Object System.Collections.Generic.List[string]
    foreach ($path in $Paths) {
        if (Test-SkippedPath $path) {
            Write-Warning "Skipping private/external path: $path"
            continue
        }

        if ((Test-ExactExistingPath $path) -or (Test-TrackedPath $path)) {
            [void] $stageable.Add($path)
        } else {
            Write-Host "Skipping missing path: $path"
        }
    }

    return $stageable.ToArray()
}

function Test-AnyStagedChanges {
    & git diff --cached --quiet
    return ($LASTEXITCODE -ne 0)
}

function Commit-Group {
    param(
        [string] $Message,
        [string[]] $Paths
    )

    $stageable = Get-StageablePaths $Paths
    if ($stageable.Count -eq 0) {
        Write-Host "No paths for: $Message"
        return
    }

    if ($PlanOnly) {
        Write-Host ''
        Write-Host "Would commit: $Message"
        foreach ($path in $stageable) {
            Write-Host "  $path"
        }
        return
    }

    foreach ($path in $stageable) {
        & git add -A -- $path
        if ($LASTEXITCODE -ne 0) {
            throw "git add failed for commit group '$Message' path '$path'"
        }
    }

    if (-not (Test-AnyStagedChanges)) {
        Write-Host "No staged changes for: $Message"
        return
    }

    & git commit -m $Message
    if ($LASTEXITCODE -ne 0) {
        throw "git commit failed for: $Message"
    }
}

if (-not $PlanOnly) {
    if ((Test-AnyStagedChanges) -and -not $Force) {
        throw 'The git index already has staged changes. Commit or unstage them first, or pass -Force to continue.'
    }
}

$groups = @(
    @{
        Message = 'repo/policy: clarify defensive public scope'
        Paths = @('.gitignore', 'README.md', 'LICENSE')
    },
    @{
        Message = 'build/style: move clang-format into vcxproj configuration'
        Paths = @('.clang-format', 'VCXProj/.clang-format')
    },
    @{
        Message = 'abi: normalize IPC contract header name'
        Paths = @('ABI/Blackbird_ipc.h', 'ABI/blackbird_ipc.h')
    },
    @{
        Message = 'abi: add diagnostics and launch subject contracts'
        Paths = @('ABI/blackbird_ioctl.h', 'ABI/blackbird_ipc.h')
    },
    @{
        Message = 'kernel/callbacks: move OS callback monitors into callbacks tree'
        Paths = @(
            'Kernel/monitors/filesystem_monitor.c',
            'Kernel/monitors/filesystem_monitor.h',
            'Kernel/monitors/handle_monitor.c',
            'Kernel/monitors/handle_monitor.h',
            'Kernel/monitors/image_monitor.c',
            'Kernel/monitors/image_monitor.h',
            'Kernel/monitors/process_monitor.c',
            'Kernel/monitors/process_monitor.h',
            'Kernel/monitors/registry_monitor.c',
            'Kernel/monitors/registry_monitor.h',
            'Kernel/monitors/thread_monitor.c',
            'Kernel/monitors/thread_monitor.h',
            'Kernel/callbacks'
        )
    },
    @{
        Message = 'kernel/core: add optional private feature boundaries'
        Paths = @(
            'Kernel/core/optional_features.h',
            'Kernel/core/optional_feature_stubs.c',
            'Kernel/core/crashdump.h'
        )
    },
    @{
        Message = 'kernel/core: add diagnostics component registry'
        Paths = @('Kernel/core/diagnostics.c', 'Kernel/core/diagnostics.h')
    },
    @{
        Message = 'kernel/core: integrate optional subsystem lifecycle'
        Paths = @(
            'Kernel/core/driver.c',
            'Kernel/core/control/control_common.c',
            'Kernel/core/control/control_dispatch_init.c',
            'Kernel/core/control/control_ioctl_handlers.c',
            'Kernel/core/control/control_private.h',
            'Kernel/core/control/control_uninit_exports.c'
        )
    },
    @{
        Message = 'kernel/core: extend runtime configuration state'
        Paths = @('Kernel/core/runtime_config.c', 'Kernel/core/runtime_config.h', 'Kernel/core/control.h')
    },
    @{
        Message = 'kernel/core: refresh Tempus debug and utility helpers'
        Paths = @(
            'Kernel/core/tempus_debug.c',
            'Kernel/core/tempus_debug.h',
            'Kernel/core/pool_compat.h',
            'Kernel/core/protection_utils.h',
            'Kernel/core/unicode_utils.h'
        )
    },
    @{
        Message = 'kernel/antivirt: add QPC timing compensation'
        Paths = @('Kernel/antivirt/qpc_timing.c', 'Kernel/antivirt/qpc_timing.h', 'Kernel/antivirt/antivirt_ntapi_firmware.c')
    },
    @{
        Message = 'kernel/antivirt: harden registry concealment flow'
        Paths = @('Kernel/antivirt/registry_concealment.c', 'Kernel/antivirt/registry_concealment.h')
    },
    @{
        Message = 'kernel/correlation: extend hollowing analysis state'
        Paths = @('Kernel/correlation/hollowing_engine.c', 'Kernel/correlation/hollowing_engine.h')
    },
    @{
        Message = 'kernel/correlation: refresh intent tracking store'
        Paths = @('Kernel/correlation/intent_store.c', 'Kernel/correlation/intent_store.h')
    },
    @{
        Message = 'kernel/hooks: update NT hook stubs and resolver'
        Paths = @(
            'Kernel/hooks/asm/ntapi_stubs.asm',
            'Kernel/hooks/hook/ntapi_hook.c',
            'Kernel/hooks/hook/ntapi_hook.h',
            'Kernel/hooks/hook/ntapi_hook_ldasm.c',
            'Kernel/hooks/hook/ntapi_hook_ldasm.h',
            'Kernel/hooks/hook/ntapi_hook_resolve.c'
        )
    },
    @{
        Message = 'kernel/ntapi: expand NT monitor coverage'
        Paths = @(
            'Kernel/hooks/monitor/ntapi_monitor.c',
            'Kernel/hooks/monitor/ntapi_monitor.h',
            'Kernel/hooks/monitor/ntapi_monitor_hooks.c',
            'Kernel/hooks/monitor/ntapi_monitor_private.h'
        )
    },
    @{
        Message = 'kernel/monitors: update anti-tamper and APC monitors'
        Paths = @('Kernel/monitors/anti_tamper.c', 'Kernel/monitors/anti_tamper.h', 'Kernel/monitors/apc_monitor.c', 'Kernel/monitors/apc_monitor.h')
    },
    @{
        Message = 'kernel/telemetry: refresh ETW telemetry bridge'
        Paths = @('Kernel/telemetry/etw.c', 'Kernel/telemetry/etw.h')
    },
    @{
        Message = 'kernel/include: add native PEB and TEB declarations'
        Paths = @('Kernel/include')
    },
    @{
        Message = 'controller/core: normalize private headers'
        Paths = @('UserMode/controller/core/Blackbird_controller_private.h', 'UserMode/controller/core/controller_private.h')
    },
    @{
        Message = 'controller/core: refresh controller entrypoint logging'
        Paths = @('UserMode/controller/Blackbird_controller.cpp', 'UserMode/controller/controller.cpp')
    },
    @{
        Message = 'controller/injection: split launch helper modules'
        Paths = @(
            'UserMode/controller/core/injection/Blackbird_controller_injection.cpp',
            'UserMode/controller/core/injection/Blackbird_controller_injection.h',
            'UserMode/controller/core/injection/common.cpp',
            'UserMode/controller/core/injection/environment.cpp',
            'UserMode/controller/core/injection/hook.cpp',
            'UserMode/controller/core/injection/image.cpp',
            'UserMode/controller/core/injection/injection.cpp',
            'UserMode/controller/core/injection/injection.h',
            'UserMode/controller/core/injection/internal.h',
            'UserMode/controller/core/injection/launch.cpp',
            'UserMode/controller/core/injection/token.cpp'
        )
    },
    @{
        Message = 'controller/ipc: split pipe protocol handlers'
        Paths = @(
            'UserMode/controller/core/ipc/Blackbird_controller_ipc.cpp',
            'UserMode/controller/core/ipc/ipc.cpp',
            'UserMode/controller/core/ipc/ipc_hook_support.cpp',
            'UserMode/controller/core/ipc/ipc_internal.h',
            'UserMode/controller/core/ipc/ipc_launch.cpp',
            'UserMode/controller/core/ipc/ipc_proxy.cpp',
            'UserMode/controller/core/ipc/ipc_shared_ring.cpp'
        )
    },
    @{
        Message = 'controller/monitoring: clean ETW and subscription modules'
        Paths = @(
            'UserMode/controller/core/monitoring/Blackbird_controller_etw_monitor.cpp',
            'UserMode/controller/core/monitoring/Blackbird_controller_subscriptions.cpp',
            'UserMode/controller/core/monitoring/etw_monitor.cpp',
            'UserMode/controller/core/monitoring/subscriptions.cpp',
            'UserMode/controller/core/monitoring/ubscriptions.cpp'
        )
    },
    @{
        Message = 'controller/runtime: split service runtime and symbols'
        Paths = @(
            'UserMode/controller/core/runtime/Blackbird_controller_runtime.cpp',
            'UserMode/controller/core/runtime/blackbird_controller_symbol_service.cpp',
            'UserMode/controller/core/runtime/runtime.cpp',
            'UserMode/controller/core/runtime/symbol_service.cpp'
        )
    },
    @{
        Message = 'controller/runtime: add optional node launcher stub'
        Paths = @(
            'UserMode/controller/core/runtime/blackbird_controller_node_runtime.cpp',
            'UserMode/controller/core/runtime/node_runtime.cpp',
            'UserMode/controller/core/runtime/ns/ns_launcher.h',
            'UserMode/controller/core/runtime/ns/ns_launcher_public.cpp'
        )
    },
    @{
        Message = 'controller/correlation: refresh hollowing analysis'
        Paths = @('UserMode/controller/core/correlation/Blackbird_controller_hollowing.cpp', 'UserMode/controller/core/correlation/hollowing.cpp')
    },
    @{
        Message = 'controller/heuristics: refresh event classification'
        Paths = @(
            'UserMode/controller/core/heuristics/Blackbird_controller_heuristics.cpp',
            'UserMode/controller/core/heuristics/heuristics.cpp',
            'UserMode/controller/core/heuristics/heuristics.h'
        )
    },
    @{
        Message = 'usermode/dllhost: add DLL analysis host'
        Paths = @('UserMode/dllhost')
    },
    @{
        Message = 'usermode/include: add native PEB helpers'
        Paths = @('UserMode/include')
    },
    @{
        Message = 'hook/runtime: update SR71 bootstrap and launch gate'
        Paths = @(
            'UserMode/hook/dll.cpp',
            'UserMode/hook/hooks/runtime_bootstrap.cpp',
            'UserMode/hook/hooks/runtime_launch_gate.cpp',
            'UserMode/hook/hooks/runtime_private.h'
        )
    },
    @{
        Message = 'hook/runtime: harden SR71 integrity state'
        Paths = @('UserMode/hook/hooks/runtime.cpp', 'UserMode/hook/hooks/runtime.h', 'UserMode/hook/hooks/runtime_integrity.cpp')
    },
    @{
        Message = 'hook/nt: expand NT hook descriptors'
        Paths = @('UserMode/hook/hooks/nt.cpp', 'UserMode/hook/hooks/nt.h')
    },
    @{
        Message = 'hook/module: update module instrumentation'
        Paths = @('UserMode/hook/hooks/module.cpp', 'UserMode/hook/hooks/module.h')
    },
    @{
        Message = 'hook/ki: update exception dispatcher instrumentation'
        Paths = @('UserMode/hook/hooks/ki.cpp', 'UserMode/hook/hooks/ki.h')
    },
    @{
        Message = 'hook/ws: refresh Winsock telemetry hooks'
        Paths = @('UserMode/hook/hooks/ws.cpp', 'UserMode/hook/hooks/ws.h')
    },
    @{
        Message = 'hook/instrument: update owned range publication'
        Paths = @(
            'UserMode/hook/instrument/bk.cpp',
            'UserMode/hook/instrument/bk.h',
            'UserMode/hook/instrument/stacktrace.cpp',
            'UserMode/hook/instrument/stacktrace.h',
            'UserMode/hook/instrument/unlink.cpp'
        )
    },
    @{
        Message = 'hook/ipc: update hook pipe transport'
        Paths = @('UserMode/hook/ipc/pipe.cpp', 'UserMode/hook/ipc/pipe.h')
    },
    @{
        Message = 'hook/build: refresh SR71 project inputs'
        Paths = @('UserMode/hook/vcxproj/BlackbirdHook.vcxproj')
    },
    @{
        Message = 'sensor: normalize sensor source names'
        Paths = @(
            'UserMode/sensor/Blackbird_etw_printer.c',
            'UserMode/sensor/Blackbird_etw_printer.h',
            'UserMode/sensor/Blackbird_etw_props.c',
            'UserMode/sensor/Blackbird_etw_props.h',
            'UserMode/sensor/Blackbird_etw_symbols.c',
            'UserMode/sensor/Blackbird_etw_symbols.h',
            'UserMode/sensor/Blackbird_event_printer.c',
            'UserMode/sensor/Blackbird_event_printer.h',
            'UserMode/sensor/Blackbird_ioctl_test.c',
            'UserMode/sensor/Blackbird_sensor_core.c',
            'UserMode/sensor/Blackbird_sensor_core.h',
            'UserMode/sensor/Blackbird_symbol_common.c',
            'UserMode/sensor/Blackbird_symbol_common.h',
            'UserMode/sensor/Blackbird_symbol_resolver.c',
            'UserMode/sensor/Blackbird_symbol_resolver.h',
            'UserMode/sensor/Blackbird_test_report_html.c',
            'UserMode/sensor/Blackbird_test_report_html.h',
            'UserMode/sensor/etw_printer.c',
            'UserMode/sensor/etw_printer.h',
            'UserMode/sensor/etw_props.c',
            'UserMode/sensor/etw_props.h',
            'UserMode/sensor/etw_symbols.c',
            'UserMode/sensor/etw_symbols.h',
            'UserMode/sensor/event_printer.c',
            'UserMode/sensor/event_printer.h',
            'UserMode/sensor/ioctl_test.c',
            'UserMode/sensor/sensor_core.c',
            'UserMode/sensor/sensor_core.h',
            'UserMode/sensor/symbol_common.c',
            'UserMode/sensor/symbol_common.h',
            'UserMode/sensor/symbol_resolver.c',
            'UserMode/sensor/symbol_resolver.h',
            'UserMode/sensor/test_report_html.c',
            'UserMode/sensor/test_report_html.h'
        )
    },
    @{
        Message = 'sensor/core: normalize sensor protocol modules'
        Paths = @(
            'UserMode/sensor/core/Blackbird_sensor_core_etw.c',
            'UserMode/sensor/core/Blackbird_sensor_core_internal.h',
            'UserMode/sensor/core/Blackbird_sensor_core_protocol.c',
            'UserMode/sensor/core/sensor_core_etw.c',
            'UserMode/sensor/core/sensor_core_internal.h',
            'UserMode/sensor/core/sensor_core_protocol.c'
        )
    },
    @{
        Message = 'sensor/tests: normalize ioctl test harness'
        Paths = @(
            'UserMode/sensor/tests/Blackbird_ioctl_test_env.c',
            'UserMode/sensor/tests/Blackbird_ioctl_test_etw.c',
            'UserMode/sensor/tests/Blackbird_ioctl_test_intent.c',
            'UserMode/sensor/tests/Blackbird_ioctl_test_internal.h',
            'UserMode/sensor/tests/Blackbird_ioctl_test_ioctl.c',
            'UserMode/sensor/tests/Blackbird_ioctl_test_main.c',
            'UserMode/sensor/tests/Blackbird_ioctl_test_report.c',
            'UserMode/sensor/tests/ioctl_test_env.c',
            'UserMode/sensor/tests/ioctl_test_etw.c',
            'UserMode/sensor/tests/ioctl_test_intent.c',
            'UserMode/sensor/tests/ioctl_test_internal.h',
            'UserMode/sensor/tests/ioctl_test_ioctl.c',
            'UserMode/sensor/tests/ioctl_test_main.c',
            'UserMode/sensor/tests/ioctl_test_report.c'
        )
    },
    @{
        Message = 'sensor/docs: refresh sensor usage notes'
        Paths = @('UserMode/sensor/README.md')
    },
    @{
        Message = 'ui/interop: add backend and native bindings'
        Paths = @(
            'Client/analysis/Interop/BlackbirdNative.Launch.cs',
            'Client/analysis/Interop/BlackbirdNative.cs',
            'Client/analysis/Interop/BkdcNative.cs',
            'Client/analysis/Interop/Kernel32Native.cs'
        )
    },
    @{
        Message = 'ui/models: add disassembly and trust models'
        Paths = @(
            'Client/analysis/Models/BlackbirdBackendModels.cs',
            'Client/analysis/Models/DiagnosticsState.cs',
            'Client/analysis/Models/GraphExplorerItem.cs',
            'Client/analysis/Models/InspectorModels.cs',
            'Client/analysis/Models/LaunchProfile.cs',
            'Client/analysis/Models/MemoryDisassemblyRequestedEventArgs.cs',
            'Client/analysis/Models/PaneHeaderDragEventArgs.cs',
            'Client/analysis/Models/PerformanceSample.cs',
            'Client/analysis/Models/SignatureTrustState.cs',
            'Client/analysis/Models/StackFrameRow.cs',
            'Client/analysis/Models/TelemetryEvent.cs',
            'Client/analysis/Models/ThreadStackSessionModels.cs'
        )
    },
    @{
        Message = 'ui/controls: refresh timeline and performance controls'
        Paths = @(
            'Client/analysis/Controls/BulkObservableCollection.cs',
            'Client/analysis/Controls/PerformanceChartControl.cs',
            'Client/analysis/Controls/SparklinePreviewControl.cs',
            'Client/analysis/Controls/TimeSeriesBuffer.cs',
            'Client/analysis/Controls/TimelineControl.cs'
        )
    },
    @{
        Message = 'ui/services: add launch orchestration service'
        Paths = @(
            'Client/analysis/Services/AnalysisLaunchService.cs',
            'Client/analysis/Services/BlackbirdPreflight.cs',
            'Client/analysis/Services/BlackbirdServiceControl.cs',
            'Client/analysis/Services/LaunchHookOptions.cs'
        )
    },
    @{
        Message = 'ui/services: add runtime configuration service'
        Paths = @(
            'Client/analysis/Services/RuntimeConfigService.cs',
            'Client/analysis/Shell/MainWindow.RuntimeConfig.cs',
            'Client/analysis/Shell/MainWindow.RuntimeConfigApi.cs',
            'Client/analysis/runtimeconfig.template.json'
        )
    },
    @{
        Message = 'ui/services: improve backend session lifecycle'
        Paths = @(
            'Client/analysis/Services/BlackbirdBackendSession.cs',
            'Client/analysis/Services/BlackbirdControlDeviceSession.cs',
            'Client/analysis/Services/BoundedStringPool.cs',
            'Client/analysis/Services/DebugConsoleService.cs',
            'Client/analysis/Services/OutputCapture.cs'
        )
    },
    @{
        Message = 'ui/services: add component identity helper'
        Paths = @(
            'Client/analysis/Services/ComponentIdentityService.cs'
        )
    },
    @{
        Message = 'ui/capture: refactor archive storage primitives'
        Paths = @(
            'Client/analysis/Services/Capture/CaptureArchiveModels.cs',
            'Client/analysis/Services/Capture/CaptureArchiveStorage.cs',
            'Client/analysis/Services/Capture/Lz4BlockCodec.cs',
            'Client/analysis/Services/Capture/SqliteDatabase.cs',
            'Client/analysis/Services/Capture/SqliteException.cs',
            'Client/analysis/Services/Capture/SqliteNative.cs',
            'Client/analysis/Services/Capture/SqliteStatement.cs'
        )
    },
    @{
        Message = 'ui/capture: add live capture projection engine'
        Paths = @('Client/analysis/Services/Capture/CaptureLiveStoreImpl.cs', 'Client/analysis/Services/Capture/CaptureProjectionEngine.cs')
    },
    @{
        Message = 'ui/services: add broker ETW event mapping'
        Paths = @(
            'Client/analysis/Services/BrokerEtwEventMapper.cs',
            'Client/analysis/Services/ProcessGraphProjectionBuilder.cs',
            'Client/analysis/Services/ProcessIdentityResolver.cs'
        )
    },
    @{
        Message = 'ui/services: update event formatting and compaction'
        Paths = @(
            'Client/analysis/Services/EventDetailFormatting.cs',
            'Client/analysis/Services/EventDetailsParsing.cs',
            'Client/analysis/Services/GroupedEventCompaction.cs',
            'Client/analysis/Services/GroupedEventPaneState.cs',
            'Client/analysis/Services/IntelDetailsProvider.cs',
            'Client/analysis/Services/TelemetryEventStore.cs'
        )
    },
    @{
        Message = 'ui/services: expand performance and stack sampling'
        Paths = @(
            'Client/analysis/Services/PerformanceSampler.cs',
            'Client/analysis/Services/ThreadStackResolver.cs',
            'Client/analysis/Services/VirtualizationProbe.cs'
        )
    },
    @{
        Message = 'ui/signature: expand signature intel analysis'
        Paths = @(
            'Client/analysis/Services/SignatureIntelService.cs',
            'Client/analysis/Services/PackerDetectionService.cs',
            'Client/analysis/Shell/MainWindow.SignatureIntel.cs',
            'Client/analysis/Windows/SignatureIntelRulesWindow.xaml',
            'Client/analysis/Windows/SignatureIntelRulesWindow.xaml.cs'
        )
    },
    @{
        Message = 'ui/session: update session storage and export flow'
        Paths = @(
            'Client/analysis/Services/SessionExportService.cs',
            'Client/analysis/Services/SessionFileStorage.cs',
            'Client/analysis/Shell/MainWindow.CaptureStore.cs',
            'Client/analysis/Shell/MainWindow.SessionStorage.cs'
        )
    },
    @{
        Message = 'ui/shell: rebuild main window backend flow'
        Paths = @(
            'Client/analysis/App.xaml.cs',
            'Client/analysis/AssemblyInfo.cs',
            'Client/analysis/Shell/MainWindow.Backend.cs',
            'Client/analysis/Shell/MainWindow.HooksArm.cs',
            'Client/analysis/Shell/MainWindow.Inspectors.cs',
            'Client/analysis/Shell/MainWindow.IntelDetailsProvider.cs',
            'Client/analysis/Shell/MainWindow.xaml',
            'Client/analysis/Shell/MainWindow.xaml.cs'
        )
    },
    @{
        Message = 'ui/shell: add settings surface'
        Paths = @(
            'Client/analysis/Settings',
            'Client/analysis/Shell/MainWindow.Settings.cs',
            'Client/analysis/Windows/InterfaceSettingsWindow.xaml',
            'Client/analysis/Windows/InterfaceSettingsWindow.xaml.cs',
            'Client/analysis/Windows/LaneSettingsWindow.xaml.cs'
        )
    },
    @{
        Message = 'ui/theme: add light theme and chrome helpers'
        Paths = @(
            'Client/analysis/Themes/DarkTheme.xaml',
            'Client/analysis/Themes/LightTheme.xaml',
            'Client/analysis/Theming/ThemedMessageBox.cs',
            'Client/analysis/Theming/UiPalette.cs',
            'Client/analysis/Theming/WindowChromeBehavior.cs',
            'Client/analysis/Theming/WindowThemeHelper.cs'
        )
    },
    @{
        Message = 'ui/panes: refresh ETW and event panes'
        Paths = @(
            'Client/analysis/Panes/EtwPane.xaml',
            'Client/analysis/Panes/EtwPane.xaml.cs',
            'Client/analysis/Panes/EventsPane.xaml',
            'Client/analysis/Panes/EventsPane.xaml.cs'
        )
    },
    @{
        Message = 'ui/panes: refresh filesystem and heuristics panes'
        Paths = @(
            'Client/analysis/Panes/FilesystemPane.xaml',
            'Client/analysis/Panes/FilesystemPane.xaml.cs',
            'Client/analysis/Panes/HeuristicsPane.xaml',
            'Client/analysis/Panes/HeuristicsPane.xaml.cs'
        )
    },
    @{
        Message = 'ui/panes: replace IPC uplink pane'
        Paths = @('Client/analysis/Panes/IpcUplinkPane.xaml', 'Client/analysis/Panes/IpcUplinkPane.xaml.cs')
    },
    @{
        Message = 'ui/panes: expand performance pane'
        Paths = @('Client/analysis/Panes/PerformancePane.xaml', 'Client/analysis/Panes/PerformancePane.xaml.cs')
    },
    @{
        Message = 'ui/panes: update process and registry panes'
        Paths = @(
            'Client/analysis/Panes/ProcessRelationsPane.xaml',
            'Client/analysis/Panes/ProcessRelationsPane.xaml.cs',
            'Client/analysis/Panes/RegistryPane.xaml',
            'Client/analysis/Panes/RegistryPane.xaml.cs'
        )
    },
    @{
        Message = 'ui/windows: update diagnostics and disassembly views'
        Paths = @(
            'Client/analysis/Windows/DiagnosticsWindow.xaml',
            'Client/analysis/Windows/DiagnosticsWindow.xaml.cs',
            'Client/analysis/Windows/DirectSyscallSuspectWindow.xaml',
            'Client/analysis/Windows/DirectSyscallSuspectWindow.xaml.cs',
            'Client/analysis/Windows/DisassemblyWindow.xaml',
            'Client/analysis/Windows/DisassemblyWindow.xaml.cs'
        )
    },
    @{
        Message = 'ui/windows: update evidence inspector views'
        Paths = @(
            'Client/analysis/Windows/ChildProcessGraphWindow.xaml.cs',
            'Client/analysis/Windows/EventLogWindow.xaml.cs',
            'Client/analysis/Windows/HandleEvidenceWindow.xaml',
            'Client/analysis/Windows/HandleEvidenceWindow.xaml.cs',
            'Client/analysis/Windows/SimpleEventDetailWindow.xaml',
            'Client/analysis/Windows/SimpleEventDetailWindow.xaml.cs',
            'Client/analysis/Windows/TelemetryInspectorWindow.xaml',
            'Client/analysis/Windows/TelemetryInspectorWindow.xaml.cs'
        )
    },
    @{
        Message = 'ui/windows: update thread stack views'
        Paths = @(
            'Client/analysis/Windows/ParallelStacksWindow.xaml',
            'Client/analysis/Windows/ParallelStacksWindow.xaml.cs',
            'Client/analysis/Windows/ThreadStackWindow.xaml',
            'Client/analysis/Windows/ThreadStackWindow.xaml.cs'
        )
    },
    @{
        Message = 'ui/windows: update launch flow'
        Paths = @(
            'Client/analysis/Windows/FaultNotificationWindow.cs',
            'Client/analysis/Windows/LaunchParametersWindow.xaml',
            'Client/analysis/Windows/LaunchParametersWindow.xaml.cs',
            'Client/analysis/Windows/LoadingWindow.xaml',
            'Client/analysis/Windows/LoadingWindow.xaml.cs',
            'Client/analysis/Windows/ProcessPickerWindow.xaml',
            'Client/analysis/Windows/ProcessPickerWindow.xaml.cs',
            'Client/analysis/Windows/StartupWelcomeWindow.xaml',
            'Client/analysis/Windows/StartupWelcomeWindow.xaml.cs'
        )
    },
    @{
        Message = 'ui/windows: refresh floating window hosts'
        Paths = @(
            'Client/analysis/Windows/Floating/EtwFloatWindow.cs',
            'Client/analysis/Windows/Floating/EventsFloatWindow.cs',
            'Client/analysis/Windows/Floating/HeuristicsFloatWindow.cs',
            'Client/analysis/Windows/Floating/MemoryInspectorWindow.cs',
            'Client/analysis/Windows/Floating/PerformanceFloatWindow.cs'
        )
    },
    @{
        Message = 'ui/host: remove legacy operator shell'
        Paths = @('Client/host')
    },
    @{
        Message = 'runner: add headless capture runner'
        Paths = @('Client/runner')
    },
    @{
        Message = 'build/scripts: replace legacy publish scripts'
        Paths = @(
            'Scripts/ci-surface.ps1',
            'Scripts/publish-interfaces.ps1',
            'Scripts/publish.NET.ps1',
            'Scripts/Compile-Win32Resource.ps1'
        )
    },
    @{
        Message = 'build/scripts: add external rule bundle normalizer'
        Paths = @('Scripts/Build-YaraBundle.ps1')
    },
    @{
        Message = 'build/scripts: update installer optional components'
        Paths = @('Scripts/installer.ps1')
    },
    @{
        Message = 'build/scripts: update remover optional cleanup'
        Paths = @('Scripts/remover.ps1')
    },
    @{
        Message = 'build/scripts: update Tempest invoke packaging'
        Paths = @('Scripts/tempest-invoke.ps1')
    },
    @{
        Message = 'build/solution: add dllhost and runner projects'
        Paths = @(
            'Blackbird.slnx',
            'VCXProj/BlackbirdDllHost.vcxproj',
            'VCXProj/BlackbirdDllHost.vcxproj.filters',
            'VCXProj/BlackbirdRunner.csproj',
            'VCXProj/Blackbird.Runner.manifest',
            'VCXProj/Blackbird.Runner.rc'
        )
    },
    @{
        Message = 'build/kernel: include diagnostics and callback sources'
        Paths = @('VCXProj/Blackbird.vcxproj', 'VCXProj/Blackbird.vcxproj.filters')
    },
    @{
        Message = 'build/controller: update controller project sources'
        Paths = @('VCXProj/BlackbirdController.vcxproj', 'VCXProj/BlackbirdController.vcxproj.filters')
    },
    @{
        Message = 'build/interface: update interface resources'
        Paths = @('VCXProj/BlackbirdInterface.csproj', 'VCXProj/Blackbird.Interface.manifest', 'VCXProj/Blackbird.Interface.rc')
    },
    @{
        Message = 'build/sensor: update sensor and ioctl test projects'
        Paths = @(
            'VCXProj/BlackbirdSensorCore.vcxproj',
            'VCXProj/BlackbirdSensorCore.vcxproj.filters',
            'VCXProj/BlackbirdIoctlTest.vcxproj',
            'VCXProj/BlackbirdIoctlTest.vcxproj.filters'
        )
    },
    @{
        Message = 'build/usermode: refresh shared props and manifests'
        Paths = @(
            'VCXProj/Blackbird.UserMode.Common.props',
            'VCXProj/Blackbird.UserMode.manifest',
            'VCXProj/Blackbird.Version.rc',
            'VCXProj/Directory.Build.props'
        )
    },
    @{
        Message = 'build/operator: retire legacy operator projects'
        Paths = @('VCXProj/BlackbirdOperator.csproj', 'VCXProj/BlackbirdExamples.vcxproj')
    },
    @{
        Message = 'build/scripts: add curated public commit helper'
        Paths = @('Scripts/commit-public-worktree.bat', 'Scripts/Commit-PublicWorktree.ps1')
    }
)

Write-Host "Repository: $repoRoot"
Write-Host "Commit groups: $($groups.Count)"
if ($PlanOnly) {
    Write-Host 'Plan-only mode: no git index or commits will be modified.'
} else {
    Write-Host 'Commit mode: commits will be created locally only. This script never pushes.'
}

foreach ($group in $groups) {
    Commit-Group -Message $group.Message -Paths $group.Paths
}

if ($PlanOnly) {
    exit 0
}

$remaining = & git status --short --untracked-files=all
$publicRemaining = @()
foreach ($line in $remaining) {
    $normalized = Convert-ToGitPath $line.Substring([Math]::Min(3, $line.Length))
    $skip = $false
    foreach ($skipPath in $privateOrExternalPaths) {
        $candidate = Convert-ToGitPath $skipPath
        if ($candidate.EndsWith('/')) {
            if ($normalized.StartsWith($candidate, [System.StringComparison]::OrdinalIgnoreCase)) {
                $skip = $true
                break
            }
        } elseif ($normalized.IndexOf($candidate, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
            $skip = $true
            break
        }
    }

    if (-not $skip) {
        $publicRemaining += $line
    }
}

if ($publicRemaining.Count -gt 0) {
    Write-Warning 'Some public-looking changes were not included in the curated commit plan:'
    foreach ($line in $publicRemaining) {
        Write-Warning "  $line"
    }
    Write-Warning 'Review these manually before pushing anything.'
}

Write-Host 'Done. Local commits were created; nothing was pushed.'
