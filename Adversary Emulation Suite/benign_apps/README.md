# Benign application corpus

These fixtures exercise representative normal application behavior while Blackbird is active. They do not require a detection. The audit passes only when the sample self-check succeeds and Blackbird emits no actionable unexpected detection.

| Case | Stack | Normal behavior exercised |
| --- | --- | --- |
| `benign_c_native` | C / Win32 | bounded file create, write, flush, readback, system information, cleanup |
| `benign_cpp_ui` | C++ / Win32 UI | calculator controls, timer-driven UI, settings roundtrip, translucent topmost status overlay |
| `benign_go_worker` | Go | loopback HTTP service/client, JSON encode/decode, sorting, settings file, graceful shutdown |
| `benign_rust_native` | Rust | bounded worker threads, calculations, settings file, cleanup |
| `benign_rust_axum_ui` | Rust / Axum / SQLite / JS | loopback web UI, ordinary Toolhelp process listing, SQLite CRUD, bundled frontend, graceful shutdown |
| `benign_electron_ui` | Electron / JS | Chromium UI, isolated preload bridge, loopback API, settings roundtrip, calculation |
| `benign_tauri_ui` | Tauri / Rust / JS | WebView UI, Rust command invocation, calculation, settings roundtrip |

Every executable is bounded and writes a `[BKAES_OUTCOME]` line to `bkaes-protection-outcome.txt` when the audit runner provides `BKAES_AUDIT_JOB_DIR`. A failed functional self-check writes `[BKAES_ASSERT_FAIL]` to `bkaes-assertions.txt` and returns nonzero.

External networking is disabled by default. The Go fixture uses a deterministic loopback API. An operator may opt into a bounded external request by setting `BKAES_EXTERNAL_URL`; the canonical audit manifest does not set it.
