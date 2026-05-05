#ifndef BK_CONTROLLER_HEURISTICS_H
#define BK_CONTROLLER_HEURISTICS_H

#include <windows.h>

/*
 * Per-PID heuristics ledger — event category flags passed to
 * ControllerHeuristicsObserveEvent to classify the event being observed.
 */
#define BK_HEUR_FLAG_ALLOC_RW 0x001u   /* MEM_COMMIT + PAGE_READWRITE alloc         */
#define BK_HEUR_FLAG_PROTECT_RX 0x002u /* NtProtectVirtualMemory → PAGE_EXECUTE_*   */
#define BK_HEUR_FLAG_WRITE_VM 0x004u   /* NtWriteVirtualMemory cross-process write   */
#define BK_HEUR_FLAG_NETWORK 0x008u    /* outbound network connect                   */
#define BK_HEUR_FLAG_DETECTION 0x010u  /* any detection-class event (sev >= 4)       */
#define BK_HEUR_FLAG_REMOTE_TH 0x020u  /* remote thread creation                     */
#define BK_HEUR_FLAG_CRED_ACCS 0x040u  /* credential-store access (lsass / SAM)      */
#define BK_HEUR_FLAG_IMG_TAMPER 0x080u /* process image tamper / ghost / herp / dopp */
#define BK_HEUR_FLAG_LOLBIN 0x100u     /* LOLBIN execution event from kernel         */
#define BK_HEUR_FLAG_DNS_QUERY 0x200u  /* GetAddrInfoW / DNS resolution              */
#define BK_HEUR_FLAG_DIRECT_IP 0x400u  /* connect to IP with no prior DNS resolution */
#define BK_HEUR_FLAG_SUSP_PORT 0x800u  /* connect to a high-risk port                */

/* Severity thresholds for aggregate-score compound detections */
#define BK_HEUR_AGGREGATE_HIGH_SCORE 20u
#define BK_HEUR_AGGREGATE_MED_SCORE 12u

/* LOTL pressure scoring thresholds */
#define BK_HEUR_LOTL_LOW_SCORE 15u
#define BK_HEUR_LOTL_HIGH_SCORE 25u

/* Injection chain stage bits — passed to ControllerInjectionChainObserve */
#define BK_CHAIN_STAGE_OPEN 0x01u    /* NtOpenProcess with VM_WRITE | VM_OP        */
#define BK_CHAIN_STAGE_ALLOC 0x02u   /* NtAllocateVirtualMemory remote             */
#define BK_CHAIN_STAGE_WRITE 0x04u   /* NtWriteVirtualMemory remote                */
#define BK_CHAIN_STAGE_PROTECT 0x08u /* NtProtectVirtualMemory remote + exec bits  */
#define BK_CHAIN_STAGE_EXEC 0x10u    /* NtCreateThreadEx / NtQueueApcThread / NtSetContextThread */

/* Suspicious destination ports flagged by CheckSuspiciousPort */
#define BK_HEUR_DNS_CALL_TUNNEL_THRESHOLD 20u /* GetAddrInfoW calls/60s to trigger tunnel suspect */
#define BK_HEUR_DNS_NAME_TUNNEL_LENGTH 40u    /* hostname char length threshold for tunnel suspect */

VOID ControllerHeuristicsInitialize(VOID);
VOID ControllerHeuristicsUninitialize(VOID);
VOID ControllerHeuristicsObserveEvent(_In_ DWORD Pid, _In_ UINT32 Severity, _In_ UINT32 HeurFlags);
VOID ControllerInjectionChainObserve(_In_ DWORD CallerPid, _In_ DWORD TargetPid, _In_ UINT32 StageBit);

/* DNS correlation helpers */
VOID ControllerHeuristicsObserveDns(_In_ DWORD Pid, _In_z_ PCSTR Hostname);
VOID ControllerHeuristicsLookupDns(_In_ DWORD Pid, _In_z_ PCSTR IpStr, _Out_writes_z_(OutChars) PSTR HostnameOut,
                                   _In_ size_t OutChars);
VOID ControllerHeuristicsObserveDirectIpConnect(_In_ DWORD Pid, _In_z_ PCSTR IpStr, _In_ UINT16 Port);

#endif /* BK_CONTROLLER_HEURISTICS_H */
