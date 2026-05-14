#ifndef BK_HOLLOWING_ENGINE_H
#define BK_HOLLOWING_ENGINE_H

#include <ntdef.h>

NTSTATUS
BkhloEngineInitialize(VOID);

VOID BkhloEngineUninitialize(VOID);

BOOLEAN
BkhloEngineSelfCheck(VOID);

BOOLEAN
BkhloResolveThreadCorrelation(_In_ HANDLE ProcessId, _In_opt_ HANDLE PreferredCreatorPid, _In_ UINT32 WindowMs,
                              _Out_opt_ HANDLE *ResolvedActorPid, _Out_opt_ UINT32 *CorrelationFlags,
                              _Out_opt_ UINT32 *CorrelationAccessMask, _Out_opt_ UINT32 *CorrelationAgeMs);

VOID BkhloObserveThread(_In_ HANDLE ProcessId, _In_opt_ HANDLE ActorPid, _In_ BOOLEAN OutsideMainImage,
                        _In_ BOOLEAN GotStart, _In_ BOOLEAN StartRegionExecutable, _In_ BOOLEAN StartRegionNonImage,
                        _In_ UINT32 CorrelationFlags, _In_ UINT32 CorrelationAccessMask, _In_ UINT32 CorrelationAgeMs);

#endif
