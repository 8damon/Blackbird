# Usage Examples

This folder contains practical usage examples. Add new examples here as they evolve.

Examples

- `usage/stdlib-ioctl-client.c`: Minimal IOCTL subscription loop using `BlackbirdSensorCore`.
- `usage/stdlib-etw-consumer.c`: Minimal ETW session using `BlackbirdSensorCore`.
- `usage/thread-injection.md`: Detect remote thread injection via detection telemetry.
- `usage/thread-injection.c`: ETW consumer that alerts on thread injection detections.
- `usage/injection-intent-chain.md`: Detect hollowing/manual-map intent chains.
- `usage/injection-intent-chain.c`: ETW consumer that alerts on injection intent detections.
- `usage/runbooks.md`: Step-by-step runbooks for labs/VMs.

Notes

- Prefer `BlackbirdSensorCore` for new integrations.
- Keep examples focused and short; reference `USAGE.md` for high-level flow.

