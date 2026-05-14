#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#ifndef NOMINMAX
#define NOMINMAX
#endif

#ifndef _WINSOCKAPI_
#define _WINSOCKAPI_
#endif

#include <Windows.h>
#include <winternl.h>
#include <intrin.h>

typedef struct _BB_LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    union
    {
        UCHAR FlagGroup[4];
        ULONG Flags;
    };
    USHORT ObsoleteLoadCount;
    USHORT TlsIndex;
    LIST_ENTRY HashLinks;
    ULONG TimeDateStamp;
    PVOID EntryPointActivationContext;
    PVOID Lock;
    PVOID DdagNode;
    LIST_ENTRY NodeModuleLink;
    PVOID LoadContext;
    PVOID ParentDllBase;
    PVOID SwitchBackContext;
} BB_LDR_DATA_TABLE_ENTRY, *PBB_LDR_DATA_TABLE_ENTRY;

typedef struct _BB_PEB_LDR_DATA
{
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} BB_PEB_LDR_DATA, *PBB_PEB_LDR_DATA;

typedef struct _BB_PEB
{
    BYTE InheritedAddressSpace;
    BYTE ReadImageFileExecOptions;
    BYTE BeingDebugged;
    BYTE BitField;
    PVOID Mutant;
    PVOID ImageBaseAddress;
    PBB_PEB_LDR_DATA Ldr;
} BB_PEB, *PBB_PEB;

typedef struct _BB_CLIENT_ID
{
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} BB_CLIENT_ID, *PBB_CLIENT_ID;

typedef struct _BB_INITIAL_TEB
{
    PVOID StackBase;
    PVOID StackLimit;
    PVOID StackAllocation;
} BB_INITIAL_TEB, *PBB_INITIAL_TEB;

#if defined(__cplusplus)
#if defined(_M_X64)
#pragma intrinsic(__readgsqword)
#elif defined(_M_IX86)
#pragma intrinsic(__readfsdword)
#endif

static __forceinline PBB_PEB BbCurrentPeb() noexcept
{
#if defined(_M_X64)
    return reinterpret_cast<PBB_PEB>(__readgsqword(0x60));
#elif defined(_M_IX86)
    return reinterpret_cast<PBB_PEB>(__readfsdword(0x30));
#else
    return nullptr;
#endif
}
#endif
