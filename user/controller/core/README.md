# Sleepwalker Controller Core Layout

This folder is organized by responsibility so monitoring, correlation, and service plumbing evolve independently.

## Modules

- `monitoring/`
  - `sleepwalker_controller_subscriptions.inc`
    - Client subscription tracking
    - Driver PID programming
    - Per-client queueing for driver and ETW events
    - Dynamic PID graph expansion (relation-driven), TTL pruning, and descendant cleanup
  - `sleepwalker_controller_etw_monitor.inc`
    - ETW property extraction helpers
    - ETW event-to-client matching
    - ETW dispatch fanout
    - ETW relation-based graph expansion (explicit actor/target fields per ETW family)

- `correlation/`
  - `sleepwalker_controller_hollowing.inc`
    - MARK accumulation
    - Hollowing heuristics/correlation
    - Synthetic detection emission

- `ipc/`
  - `sleepwalker_controller_ipc.inc`
    - Pipe protocol validation/response handling
    - Subscribe/unsubscribe/query commands

- `runtime/`
  - `sleepwalker_controller_runtime.inc`
    - Thread entrypoints and ETW callback
    - Start/stop lifecycle and service glue
    - ProcessTelemetry-driven expansion (`creator/parent -> child`)

## Include Order Contract

`sleepwalker_controller.c` includes modules in this order:
1. `monitoring/sleepwalker_controller_subscriptions.inc`
2. `monitoring/sleepwalker_controller_etw_monitor.inc`
3. `correlation/sleepwalker_controller_hollowing.inc`
4. `ipc/sleepwalker_controller_ipc.inc`
5. `runtime/sleepwalker_controller_runtime.inc`

This ordering guarantees correlation can consume monitoring ETW helpers and dispatch APIs without circular dependencies.
