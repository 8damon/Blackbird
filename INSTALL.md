# Blackbird Install and Operator Workflow

## Prerequisites

- Windows VM for analysis/testing
- Visual Studio + WDK (KMDF toolchain)
- administrative shell
- test-signing enabled for non-production certs

## Conventions

- `<REPO_ROOT>` means the local folder where you cloned this repository.
- Commands below assume an elevated terminal.

## 1) Build The Projects

Build the driver and the user-mode pieces you need:

- `vcxproj/Blackbird.vcxproj`
- `vcxproj/BlackbirdController.vcxproj`
- `vcxproj/BlackbirdSensorCore.vcxproj`
- `vcxproj/BlackbirdIoctlTest.vcxproj`
- `vcxproj/BlackbirdInterface.csproj`
- `vcxproj/BlackbirdExamples.vcxproj`

## 2) Install / Update Driver And Controller

```powershell
cd "<REPO_ROOT>"
powershell -ExecutionPolicy Bypass -File .\scripts\installer.ps1
```

Optional runtime defaults:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\installer.ps1 -EnableAntiVirtualization -EnableControllerHiding
```

What the installer does:

- copies `blackbird.sys`, `BlackbirdController.exe`, and `J58.dll`
- recreates the driver and controller services
- waits for locked files and pending service deletions to clear
- seeds runtime default registry values for anti-virtualization and concealment

## 3) Validate Service State

```bat
sc query blackbird
sc query BlackbirdController
```

## 4) Remove The Stack

```powershell
cd "<REPO_ROOT>"
powershell -ExecutionPolicy Bypass -File .\scripts\remover.ps1
```

## 5) Validate The IOCTL / Broker Path

```bat
cd /d "<REPO_ROOT>"
.\x64\Debug\BlackbirdTestSuite.exe
```

## 6) Run The Interface

```bat
cd /d "<REPO_ROOT>"
.\interface\analysis\bin\Debug\net9.0-windows\BlackbirdInterface.exe
```

## Notes

- Control plane endpoint: `\\.\Global\BlackbirdCtl` preferred, `\\.\BlackbirdCtl` legacy
- Driver control-device ACL remains `SYSTEM` and `Administrators`
- Controller now separates privileged control traffic from SR71 hook-ingest traffic
- Session archives use the `.bkcap` extension