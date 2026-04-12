#ifndef BLACKBIRD_TEMPUS_DEBUG_H
#define BLACKBIRD_TEMPUS_DEBUG_H

#include <ntddk.h>
#include "..\..\ABI\blackbird_ioctl.h"

#ifdef BLACKBIRD_TEMPUS_DEBUG

NTSTATUS BLACKBIRDTempusInitialize(VOID);
VOID BLACKBIRDTempusUninitialize(VOID);
BOOLEAN BLACKBIRDTempusIsEnabled(VOID);
UINT64 BLACKBIRDTempusGetQpcFrequency(VOID);
ULONGLONG BLACKBIRDTempusEnter(_In_ UINT32 SubsystemId);
VOID BLACKBIRDTempusLeave(_In_ UINT32 SubsystemId, _In_ ULONGLONG StartQpc);
VOID BLACKBIRDTempusQueryStats(_Out_writes_(BucketCount) PBLACKBIRD_TEMPUS_BUCKET Buckets, _In_ UINT32 BucketCount,
                               _Out_opt_ UINT64 *QpcFrequency);

#else

#define BLACKBIRDTempusInitialize() STATUS_SUCCESS
#define BLACKBIRDTempusUninitialize() ((VOID)0)
#define BLACKBIRDTempusIsEnabled() (FALSE)
#define BLACKBIRDTempusGetQpcFrequency() (0ULL)
#define BLACKBIRDTempusEnter(_SubsystemId) (0ULL)
#define BLACKBIRDTempusLeave(_SubsystemId, _StartQpc) ((VOID)(_StartQpc))
#define BLACKBIRDTempusQueryStats(_Buckets, _BucketCount, _QpcFrequency) ((VOID)0)

#endif

#endif
