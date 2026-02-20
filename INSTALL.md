# Stinger Install and Operator Workflow

## Prerequisites

- Windows VM for analysis/testing
- Visual Studio + WDK (KMDF toolchain)
- Administrative shell
- Test-signing enabled for non-production certs

## 1) Build the Driver

Open `Stinger.slnx` and build:

- Project: `projects/Stinger.vcxproj`
- Platform: `x64`
- Configuration: `Debug` or `Release`

Expected artifacts (default):

- `x64\Debug\stingr.sys`
- `x64\Debug\Stinger.inf`

## 2) Install the Driver Package

From elevated terminal:

```bat
pnputil /add-driver "C:\$ARSENAL\Kernel\Tartan\x64\Debug\Stinger.inf" /install
```

Validate package presence:

```bat
pnputil /enum-drivers | findstr /i stinger
```

## 3) Start/Stop Service

```bat
sc query stingr
sc start stingr
sc stop stingr
```

## 4) Build User-Mode Tools

Build one or more:

- `projects/StingerClient.vcxproj`
- `projects/StingerIoctlTest.vcxproj`
- `projects/StingerEtwProc.vcxproj`

Alternative direct compile path:

```bat
cd C:\$ARSENAL\Kernel\Tartan\user\sensor
build_client.cmd
build_sensor.cmd
```

## 5) Validate IOCTL Path (Recommended)

```bat
cd C:\$ARSENAL\Kernel\Tartan
.\x64\Debug\StingerIoctlTest.exe
```

## 6) Run Targeted Operator Client

```bat
cd C:\$ARSENAL\Kernel\Tartan
.\x64\Debug\StingerClient.exe 4242 handle,memory,thread
```

## 7) Run ETW Sensor (Optional)

```bat
cd C:\$ARSENAL\Kernel\Tartan
.\x64\Debug\StingerEtwProc.exe
```

## Notes

- Control plane endpoint: `\\.\StingerCtl`
- ACL policy: `SYSTEM` and `Administrators`
- Driver project is kernel-only; user tooling is isolated under dedicated user-mode projects
