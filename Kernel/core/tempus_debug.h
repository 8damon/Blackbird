#ifndef BK_TEMPUS_DEBUG_H
#define BK_TEMPUS_DEBUG_H

#include <ntddk.h>
#include "..\..\abi\blackbird_ioctl.h"

#ifdef BK_TEMPUS_DEBUG

NTSTATUS BktmpInitialize(VOID);
VOID BktmpUninitialize(VOID);
BOOLEAN BktmpIsEnabled(VOID);
UINT64 BktmpGetQpcFrequency(VOID);
ULONGLONG BktmpEnter(_In_ UINT32 SubsystemId);
VOID BktmpLeave(_In_ UINT32 SubsystemId, _In_ ULONGLONG StartQpc);
VOID BktmpQueryStats(_Out_writes_(BucketCount) PBK_TEMPUS_BUCKET Buckets, _In_ UINT32 BucketCount,
                     _Out_opt_ UINT64 *QpcFrequency);

#else

#define BktmpInitialize() STATUS_SUCCESS
#define BktmpUninitialize() ((VOID)0)
#define BktmpIsEnabled() (FALSE)
#define BktmpGetQpcFrequency() (0ULL)
#define BktmpEnter(_SubsystemId) (0ULL)
#define BktmpLeave(_SubsystemId, _StartQpc) ((VOID)(_StartQpc))
#define BktmpQueryStats(_Buckets, _BucketCount, _QpcFrequency) ((VOID)0)

#endif

#endif
