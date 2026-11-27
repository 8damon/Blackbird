# Synthetic file-I/O fixture

This standalone Windows sample creates sixteen new 1 KiB files in a fresh
temporary directory and performs a bounded sequence of reads and writes. It uses
the public byte sequence 0..255 repeated four times for its high-entropy pattern.
It contains no encryption, existing-directory traversal, networking, or deletion.

Build from an MSVC Developer Command Prompt in this directory:

```cmd
mkdir bin
cl /nologo /W4 /WX /EHsc fixture.cpp /Fo:bin\fixture.obj /Fe:bin\fixture.exe
bin\fixture.exe burst
```

Set `TEMP` and `TMP` to a dedicated test directory before running. The sample
prints its PID, selected mode and newly created directory, waits fifteen seconds
so observation tools can be prepared, then performs the selected operations.

| Mode | File operations without external intervention |
|---|---|
| `burst` | Replace zero-filled contents across all sixteen files with the repeating byte pattern. |
| `low` | Read and rewrite zero-filled contents. |
| `already-high` | Initialize files with the pattern, then read and rewrite that same pattern. |
| `single-file` | Repeatedly reset and transform only the first file. |
| `slow` | Transform all sixteen files with a 1.2-second delay after each iteration. |
| `failed-write` | Attempt writes through read-only handles; ordinary Windows access checks reject them. |

The final output reports successful operations, access-denied results, unexpected
results, elapsed operation time and the created directory. Inspect file contents
independently when evaluating a monitoring tool. The sample does not determine
whether another tool detected or prevented an operation.

Files remain available for inspection. After testing, remove only the exact
directory printed by this invocation. No automatic or recursive cleanup is
performed by the sample.
