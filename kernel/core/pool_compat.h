#ifndef BLACKBIRD_POOL_COMPAT_H
#define BLACKBIRD_POOL_COMPAT_H

typedef PVOID(NTAPI *BLACKBIRD_EX_ALLOCATE_POOL2_FN)(_In_ POOL_FLAGS Flags, _In_ SIZE_T NumberOfBytes, _In_ ULONG Tag);

static __forceinline PVOID BLACKBIRDAllocatePoolCompat(_In_ POOL_FLAGS Flags, _In_ SIZE_T NumberOfBytes, _In_ ULONG Tag)
{
    static volatile LONG resolved = 0;
    static volatile BLACKBIRD_EX_ALLOCATE_POOL2_FN allocatePool2 = NULL;

    if (InterlockedCompareExchange(&resolved, 0, 0) == 0)
    {
        UNICODE_STRING name;

        RtlInitUnicodeString(&name, L"ExAllocatePool2");
        allocatePool2 = (BLACKBIRD_EX_ALLOCATE_POOL2_FN)MmGetSystemRoutineAddress(&name);
        InterlockedExchange(&resolved, 1);
    }

    if (allocatePool2 != NULL)
    {
        return allocatePool2(Flags, NumberOfBytes, Tag);
    }

    {
        POOL_TYPE poolType;
        PVOID allocation;

        poolType = ((Flags & POOL_FLAG_PAGED) != 0) ? PagedPool : NonPagedPoolNx;
        allocation = ExAllocatePoolWithTag(poolType, NumberOfBytes, Tag);
        if (allocation != NULL && (Flags & POOL_FLAG_UNINITIALIZED) == 0)
        {
            RtlZeroMemory(allocation, NumberOfBytes);
        }
        return allocation;
    }
}

#endif


