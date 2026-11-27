# Blackbird Adversary Emulation Suite

Imported from the [public AES repository](https://github.com/Ryftenius/Adversary-Emulation-Suite)
at commit `50514c643d511b007bb21043756f5c79ac9b11a7`.

The Blackbird Adversary Emulation Suite is an extension of Blackbird for validating Blackbird telemetry,
correlation, and detection coverage in controlled defensive labs.

This directory is not a general-purpose offensive toolkit. It exists to exercise Blackbird's sensors and
detection logic with inert, bounded samples. The samples are designed for Blackbird capability testing only and
must not be used for intrusion, post-exploitation, evasion development, unauthorized monitoring, or any other
dual-use/offensive purpose.

## Layout

- `VCXProj/` - Visual Studio solution and project files.
- `src/` and `include/` - core AES console application sources.
- `common/` - shared sample dispatcher and support code.
- `apc/`, `beacon/`, `hollowing/`, `injection/`, `kerberos/`, `loader/`, `lotl/`, `lpe/`, `mem/`, `network/`, `process/`,
  `registry/`, `service/`, `sxs/`, `syscall/`, `benign/` - sample categories built by the category vcxprojs.
- `benign_apps/` - cross-language normal-application corpus used to measure actionable false-positive noise.
- `Scripts/` - public build and sample helper scripts.

## Build

Open `AES.slnx` or build with MSBuild:

```powershell
msbuild AES.slnx /t:Build /p:Configuration=Release /p:Platform=x64 /m
```

Build outputs are generated under platform/configuration directories such as `x64/Release/` and are intentionally
ignored by git.

To build a single sample category:

```powershell
msbuild VCXProj\AES.Samples.Syscall.vcxproj /t:Build /p:Configuration=Release /p:Platform=x64
```

To build the cross-language benign application corpus with locally installed toolchains:

```powershell
.\Scripts\Build-BenignApps.ps1 -AllowPartial
```

Omit `-AllowPartial` in validation environments where every required toolchain and UI runtime is installed. The
script uses locked, offline Cargo builds and does not install or download dependencies. See
`benign_apps/README.md` for the exercised behavior and use `manifests/benign-apps.json` with Blackbird's detection
audit runner.

The sample build script is `Build.ps1`. It can generate a local sample inventory from the suite build metadata;
generated inventories are ignored by git.

## License And Use Limits

This project is DSGL code and is governed by the `LICENSE` in this directory, as an extension of the Blackbird
Community license. Use is limited to authorized defensive testing of Blackbird. Do not redistribute generated
executables, DLLs, symbols, intermediate files, or Visual Studio local state.
