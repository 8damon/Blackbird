#include "unlink.h"

#include <windows.h>
#include <cstdint>
#include <cwchar>

#pragma comment(lib, "ntdll.lib")

typedef struct _KH_UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} KH_UNICODE_STRING;

typedef struct _KH_LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID      DllBase;
    PVOID      EntryPoint;
    ULONG      SizeOfImage;
    KH_UNICODE_STRING FullDllName;
    KH_UNICODE_STRING BaseDllName;
} KH_LDR_DATA_TABLE_ENTRY, * PKH_LDR_DATA_TABLE_ENTRY;

typedef struct _KH_PEB_LDR_DATA
{
    ULONG      Length;
    BOOLEAN    Initialized;
    PVOID      SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} KH_PEB_LDR_DATA, * PKH_PEB_LDR_DATA;

typedef struct _KH_PEB
{
    BYTE               Reserved1[2];
    BYTE               BeingDebugged;
    BYTE               Reserved2[1];
    PVOID              Reserved3[2];
    PKH_PEB_LDR_DATA   Ldr;
} KH_PEB, * PKH_PEB;

static void UnlinkListEntry(LIST_ENTRY* entry)
{
    entry->Blink->Flink = entry->Flink;
    entry->Flink->Blink = entry->Blink;
    entry->Flink = nullptr;
    entry->Blink = nullptr;
}

void UnlinkModule()
{
#if !defined(_WIN64)
    return;
#endif

    PKH_PEB peb = reinterpret_cast<PKH_PEB>(__readgsqword(0x60));
    if (!peb || !peb->Ldr)
        return;

    PKH_PEB_LDR_DATA ldr = peb->Ldr;

    LIST_ENTRY* head = &ldr->InLoadOrderModuleList;
    LIST_ENTRY* curr = head->Flink;

    while (curr != head)
    {
        PKH_LDR_DATA_TABLE_ENTRY entry =
            CONTAINING_RECORD(curr, KH_LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

        curr = curr->Flink;

        if (!entry->BaseDllName.Buffer)
            continue;

        if (_wcsicmp(entry->BaseDllName.Buffer, L"sr71.dll") != 0)
            continue;

        UnlinkListEntry(&entry->InLoadOrderLinks);
        UnlinkListEntry(&entry->InMemoryOrderLinks);
        UnlinkListEntry(&entry->InInitializationOrderLinks);
        break;
    }
}
