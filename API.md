# Blackbird API Guide

This document describes the current Blackbird control-plane and telemetry contract for engineers, detection content authors, and integrators.

## Revision and Scope

- Document revision: `2026-03-29`
- ABI source of truth: `abi/blackbird_ioctl.h`
- IPC source of truth: `abi/Blackbird_ipc.h`
- Validate against `BlackbirdTestSuite` after changing the broker or driver surface.

## At a Glance

- Control device:
  - NT: `\Device\BlackbirdCtl`
  - DOS: `\\.\Global\BlackbirdCtl` preferred, `\\.\BlackbirdCtl` legacy
- Primary broker pipe:
  - `\\.\pipe\BlackbirdController`
- Hook ingest pipe:
  - `\\.\pipe\BlackbirdHookIngest`
- Shared user-mode SDK:
  - `J58.dll` / `user/sensor/blackbird_sensor_core.h`
- ETW provider:
  - name: `Blackbird.Kernel`
  - GUID: `{D6C73F8A-6AD8-4F4B-A363-3D2FA31CD0E2}`

## Shared User-Mode SDK (`BlackbirdSensorCore`)

The preferred integration surface for user-mode consumers is:

- header: `user/sensor/blackbird_sensor_core.h`
- binary: `J58.dll`

Current high-value exports include:

- protocol selection helpers
- control-device open and subscription helpers
- query process image path
- set shutdown mode
- arm pending launch
- control process execution
- set/get runtime config
- mark interface ready
- mark controller ready
- ETW session helpers

Consumers currently using these exports:

- `BlackbirdController`
- `BlackbirdInterface`
- `BlackbirdTestSuite`

## Runtime Config

Runtime flags are defined in `abi/blackbird_ioctl.h` and persisted under the driver service `Parameters` key.

Current flags:

- `BLACKBIRD_RUNTIME_FLAG_ANTI_VIRTUALIZATION`
- `BLACKBIRD_RUNTIME_FLAG_SELF_HIDE`
- `BLACKBIRD_RUNTIME_FLAG_INTERFACE_PROTECTED_ACCESS`
- `BLACKBIRD_RUNTIME_FLAG_CONTROLLER_PROTECTED_ACCESS`

Current mode values:

- `BLACKBIRD_RUNTIME_MODE_LOITER`
- `BLACKBIRD_RUNTIME_MODE_GUIDED`

Relevant IOCTLs:

- `IOCTL_BLACKBIRD_SET_RUNTIME_CONFIG`
- `IOCTL_BLACKBIRD_GET_RUNTIME_CONFIG`
- `IOCTL_BLACKBIRD_MARK_INTERFACE_READY`
- `IOCTL_BLACKBIRD_MARK_CONTROLLER_READY`

## Control-Plane Notes

- Privileged IOCTLs are intended for the tracked Blackbird controller/interface processes.
- The controller brokers interface runtime-config and readiness calls.
- SR71 hook clients use the hook-ingest pipe and do not share the full privileged broker command surface.

## IPC Model

Current command families include:

- handshake
- subscription and event retrieval
- query process image
- set user hook target
- control process execution
- set/get runtime config
- mark interface ready
- hook publish / hook ready ingest

The control pipe and hook-ingest pipe are intentionally distinct.

## Detection Examples

Manual validation scenarios now live in `DetectionExamples.exe` rather than the old `usage/` source set.

Useful commands:

- `DetectionExamples.exe --list`
- `DetectionExamples.exe --run <scenario>`
- `DetectionExamples.exe --run-all-detection`
- `DetectionExamples.exe --run-all-benign`

## Compatibility

Pin by commit or release tag when integrating externally, and rerun `BlackbirdTestSuite` after changing:

- `abi/blackbird_ioctl.h`
- `abi/Blackbird_ipc.h`
- `user/sensor/blackbird_sensor_core.h`
- controller pipe command handling
- driver runtime-config semantics