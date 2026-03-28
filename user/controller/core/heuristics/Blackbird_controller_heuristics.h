#ifndef BLACKBIRD_CONTROLLER_HEURISTICS_H
#define BLACKBIRD_CONTROLLER_HEURISTICS_H

#include <windows.h>

/*
 * Per-PID heuristics ledger — event category flags passed to
 * ControllerHeuristicsObserveEvent to classify the event being observed.
 */
#define BLACKBIRD_HEUR_FLAG_ALLOC_RW 0x01u   /* MEM_COMMIT + PAGE_READWRITE alloc         */
#define BLACKBIRD_HEUR_FLAG_PROTECT_RX 0x02u /* NtProtectVirtualMemory → PAGE_EXECUTE_*   */
#define BLACKBIRD_HEUR_FLAG_WRITE_VM 0x04u   /* NtWriteVirtualMemory cross-process write   */
#define BLACKBIRD_HEUR_FLAG_NETWORK 0x08u    /* outbound network connect                   */
#define BLACKBIRD_HEUR_FLAG_DETECTION 0x10u  /* any detection-class event (sev >= 4)       */
#define BLACKBIRD_HEUR_FLAG_REMOTE_TH 0x20u  /* remote thread creation                     */
#define BLACKBIRD_HEUR_FLAG_CRED_ACCS 0x40u  /* credential-store access (lsass / SAM)      */
#define BLACKBIRD_HEUR_FLAG_IMG_TAMPER 0x80u /* process image tamper / ghost / herp / dopp */

/* Severity thresholds for aggregate-score compound detections */
#define BLACKBIRD_HEUR_AGGREGATE_HIGH_SCORE 20u
#define BLACKBIRD_HEUR_AGGREGATE_MED_SCORE 12u

VOID ControllerHeuristicsInitialize(VOID);
VOID ControllerHeuristicsUninitialize(VOID);
VOID ControllerHeuristicsObserveEvent(_In_ DWORD Pid, _In_ UINT32 Severity, _In_ UINT32 HeurFlags);

#endif /* BLACKBIRD_CONTROLLER_HEURISTICS_H */
