#ifndef BK_CONTROLLER_HEURISTICS_H
#define BK_CONTROLLER_HEURISTICS_H

#include <windows.h>

#define BK_HEUR_FLAG_ALLOC_RW 0x001u
#define BK_HEUR_FLAG_PROTECT_RX 0x002u
#define BK_HEUR_FLAG_WRITE_VM 0x004u
#define BK_HEUR_FLAG_NETWORK 0x008u
#define BK_HEUR_FLAG_DETECTION 0x010u
#define BK_HEUR_FLAG_REMOTE_TH 0x020u
#define BK_HEUR_FLAG_CRED_ACCS 0x040u
#define BK_HEUR_FLAG_IMG_TAMPER 0x080u
#define BK_HEUR_FLAG_LOLBIN 0x100u
#define BK_HEUR_FLAG_DNS_QUERY 0x200u
#define BK_HEUR_FLAG_DIRECT_IP 0x400u
#define BK_HEUR_FLAG_SUSP_PORT 0x800u

#define BK_HEUR_AGGREGATE_HIGH_SCORE 20u
#define BK_HEUR_AGGREGATE_MED_SCORE 12u

#define BK_HEUR_LOTL_LOW_SCORE 15u
#define BK_HEUR_LOTL_HIGH_SCORE 25u

#define BK_CHAIN_STAGE_OPEN 0x01u
#define BK_CHAIN_STAGE_ALLOC 0x02u
#define BK_CHAIN_STAGE_WRITE 0x04u
#define BK_CHAIN_STAGE_PROTECT 0x08u
#define BK_CHAIN_STAGE_EXEC 0x10u

#define BK_HEUR_DNS_CALL_TUNNEL_THRESHOLD 20u
#define BK_HEUR_DNS_NAME_TUNNEL_LENGTH 40u

VOID ControllerHeuristicsInitialize(VOID);
VOID ControllerHeuristicsUninitialize(VOID);
VOID ControllerHeuristicsObserveEvent(_In_ DWORD Pid, _In_ UINT32 Severity, _In_ UINT32 HeurFlags);
VOID ControllerInjectionChainObserve(_In_ DWORD CallerPid, _In_ DWORD TargetPid, _In_ UINT32 StageBit);

VOID ControllerHeuristicsObserveDns(_In_ DWORD Pid, _In_z_ PCSTR Hostname);
VOID ControllerHeuristicsLookupDns(_In_ DWORD Pid, _In_z_ PCSTR IpStr, _Out_writes_z_(OutChars) PSTR HostnameOut,
                                   _In_ size_t OutChars);
VOID ControllerHeuristicsObserveDirectIpConnect(_In_ DWORD Pid, _In_z_ PCSTR IpStr, _In_ UINT16 Port);

#endif
