# Blackbird Install and Operator Workflow

## Deployment/Validation Visuals

<p align="center">
  <img src="./media/TEST_PASS.png" width="700" />
</p>

## Prerequisites

- Windows VM for analysis/testing
- Visual Studio + WDK (KMDF toolchain)
- Administrative shell
- Test-signing enabled for non-production certs

## Conventions

- `<REPO_ROOT>` means the local folder where you cloned this repository.
- Commands below assume an elevated terminal.

## 1) Build the Driver

Open the solution file (`*.slnx`) in Visual Studio and build:

- Project: `vcxproj/Blackbird.vcxproj`
- Platform: `x64`
- Configuration: `Debug` or `Release`

Expected artifacts (default):

- `x64\Debug\blackbird.sys`
- `x64\Debug\Blackbird.inf`

## 2) Install the Driver Package

From elevated terminal:

```bat
cd /d "<REPO_ROOT>"
pnputil /add-driver "Blackbird.inf" /install
```

Validate package presence:

```bat
pnputil /enum-drivers | findstr /i blackbird
```

## 3) Start/Stop Service

```bat
sc query blackbird
sc start blackbird
sc stop blackbird
```

## 4) Build User-Mode Tools

Build one or more:

- `vcxproj/BlackbirdController.vcxproj`
- `vcxproj/BlackbirdIoctlTest.vcxproj`
- `vcxproj/BlackbirdSensorCore.vcxproj`
- `vcxproj/BlackbirdInterface.csproj`
- `vcxproj/BlackbirdOperator.csproj`

## 5) Install/Run Controller Service (Recommended)

Install/update the Session 0 broker service:

```powershell
cd "<REPO_ROOT>"
powershell -ExecutionPolicy Bypass -File .\usage\install-controller-service.ps1
```

Validate:

```bat
sc query BlackbirdController
```

Uninstall:

```powershell
powershell -ExecutionPolicy Bypass -File .\usage\install-controller-service.ps1 -Uninstall
```

## 6) Validate IOCTL Path (Recommended)

```bat
cd /d "<REPO_ROOT>"
.\x64\Debug\BlackbirdTestSuite.exe
```

## 7) Run The Interface

```bat
cd /d "<REPO_ROOT>"
.\interface\analysis\bin\Debug\net9.0-windows\BlackbirdInterface.exe
```

## 8) Run ETW Capture (Optional)

Use the analyst interface inspectors or a custom consumer via `BlackbirdSensorCore` (`BLACKBIRDSCStartBlackbirdEtwSession` / `BLACKBIRDSCStartDetectionEtwSession`).

## Notes

- Control plane endpoint: `\\.\BlackbirdCtl`
- ACL policy: `SYSTEM` and `Administrators`
- Driver project is kernel-only; user tooling is isolated under dedicated user-mode projects
- Session archives produced by the analyst interface use the `.bkcap` extension


