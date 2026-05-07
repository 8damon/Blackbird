#include "unlink.h"
#include "../../include/native_peb.h"

#include <windows.h>
#include <cstdint>
#include <cwchar>

#pragma comment(lib, "ntdll.lib")

namespace
{
    using LdrLockLoaderLockFn = NTSTATUS(NTAPI *)(ULONG Flags, ULONG *Disposition, ULONG_PTR *Cookie);
    using LdrUnlockLoaderLockFn = NTSTATUS(NTAPI *)(ULONG Flags, ULONG_PTR Cookie);

    struct Sr71LoaderSnapshot
    {
        PVOID DllBase;
        ULONG SizeOfImage;
        WCHAR FullDllName[260];
        WCHAR BaseDllName[64];
    };

    static Sr71LoaderSnapshot g_Sr71LoaderSnapshot{};
    static volatile LONG g_UnlinkComplete = 0;

    static bool IsLinkedListEntry(const LIST_ENTRY *entry) noexcept
    {
        if (entry == nullptr || entry->Flink == nullptr || entry->Blink == nullptr)
        {
            return false;
        }

        __try
        {
            return entry->Flink->Blink == entry && entry->Blink->Flink == entry;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    static void ResetListEntry(LIST_ENTRY *entry) noexcept
    {
        entry->Flink = entry;
        entry->Blink = entry;
    }

    static void UnlinkListEntry(LIST_ENTRY *entry) noexcept
    {
        if (!IsLinkedListEntry(entry))
        {
            ResetListEntry(entry);
            return;
        }

        entry->Blink->Flink = entry->Flink;
        entry->Flink->Blink = entry->Blink;
        ResetListEntry(entry);
    }

    static bool UnicodeEqualsInsensitive(const UNICODE_STRING &value, const wchar_t *expected) noexcept
    {
        return value.Buffer != nullptr && expected != nullptr && _wcsicmp(value.Buffer, expected) == 0;
    }

    static void CopyUnicodeString(WCHAR *dest, size_t destCount, const UNICODE_STRING &source) noexcept
    {
        if (dest == nullptr || destCount == 0)
        {
            return;
        }
        dest[0] = L'\0';
        if (source.Buffer == nullptr || source.Length == 0)
        {
            return;
        }

        size_t chars = source.Length / sizeof(WCHAR);
        if (chars >= destCount)
        {
            chars = destCount - 1;
        }
        std::wmemcpy(dest, source.Buffer, chars);
        dest[chars] = L'\0';
    }

    static void ScrubUnicodeString(UNICODE_STRING &value) noexcept
    {
        if (value.Buffer != nullptr && value.MaximumLength >= sizeof(WCHAR))
        {
            __try
            {
                SecureZeroMemory(value.Buffer, value.MaximumLength);
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
            }
        }
        value.Length = 0;
        value.MaximumLength = 0;
        value.Buffer = nullptr;
    }

    static void SnapshotAndConcealEntry(PBB_LDR_DATA_TABLE_ENTRY entry) noexcept
    {
        g_Sr71LoaderSnapshot.DllBase = entry->DllBase;
        g_Sr71LoaderSnapshot.SizeOfImage = entry->SizeOfImage;
        CopyUnicodeString(g_Sr71LoaderSnapshot.FullDllName, RTL_NUMBER_OF(g_Sr71LoaderSnapshot.FullDllName),
                          entry->FullDllName);
        CopyUnicodeString(g_Sr71LoaderSnapshot.BaseDllName, RTL_NUMBER_OF(g_Sr71LoaderSnapshot.BaseDllName),
                          entry->BaseDllName);

        UnlinkListEntry(&entry->InLoadOrderLinks);
        UnlinkListEntry(&entry->InMemoryOrderLinks);
        UnlinkListEntry(&entry->InInitializationOrderLinks);
        UnlinkListEntry(&entry->HashLinks);
        UnlinkListEntry(&entry->NodeModuleLink);

        ScrubUnicodeString(entry->FullDllName);
        ScrubUnicodeString(entry->BaseDllName);
        entry->ObsoleteLoadCount = 0;
    }

}

void UnlinkModulePEB()
{
#if !defined(_WIN64)
    return;
#endif
    if (InterlockedCompareExchange(&g_UnlinkComplete, 1, 0) != 0)
    {
        return;
    }

    PBB_PEB peb = BbCurrentPeb();
    if (!peb || !peb->Ldr)
        return;

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    auto lockLoader =
        ntdll != nullptr ? reinterpret_cast<LdrLockLoaderLockFn>(GetProcAddress(ntdll, "LdrLockLoaderLock")) : nullptr;
    auto unlockLoader = ntdll != nullptr
                            ? reinterpret_cast<LdrUnlockLoaderLockFn>(GetProcAddress(ntdll, "LdrUnlockLoaderLock"))
                            : nullptr;
    ULONG_PTR cookie = 0;
    ULONG disposition = 0;
    bool locked = lockLoader != nullptr && unlockLoader != nullptr && NT_SUCCESS(lockLoader(0, &disposition, &cookie));

    PBB_PEB_LDR_DATA ldr = peb->Ldr;

    LIST_ENTRY *head = &ldr->InLoadOrderModuleList;
    LIST_ENTRY *curr = head->Flink;

    while (curr != nullptr && curr != head)
    {
        PBB_LDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(curr, BB_LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

        curr = curr->Flink;

        if (!UnicodeEqualsInsensitive(entry->BaseDllName, L"SR71.dll"))
            continue;

        SnapshotAndConcealEntry(entry);
        break;
    }

    if (locked)
    {
        unlockLoader(0, cookie);
    }
}
