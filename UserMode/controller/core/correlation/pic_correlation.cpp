#include "../controller_private.h"

namespace
{
    inline constexpr DWORD kPicFactSlots = 256u;
    inline constexpr ULONGLONG kPicCorrelationWindowMs = 15000ull;

    struct CONTROLLER_PIC_FACT
    {
        DWORD ProcessId = 0;
        DWORD ThreadId = 0;
        ULONGLONG LastTick = 0;
        UINT64 ReturnPc = 0;
        UINT64 StackPointer = 0;
        UINT64 AllocationBase = 0;
        UINT64 RegionSize = 0;
        UINT32 Protect = 0;
        UINT32 Count = 0;
    };

    SRWLOCK g_PicFactsLock = SRWLOCK_INIT;
    CONTROLLER_PIC_FACT g_PicFacts[kPicFactSlots]{};
    volatile LONG g_PicNextSlot = -1;

    bool PicEventIsDirectSyscall(_In_ const BKIPC_ETW_EVENT *Event)
    {
        return Event != nullptr && ControllerAsciiEqualsInsensitive(Event->DetectionName, "PIC_DIRECT_SYSCALL_SUSPECT");
    }

    DWORD PicPrimaryPid(_In_ const BKIPC_ETW_EVENT *Event)
    {
        if (Event == nullptr)
        {
            return 0;
        }
        if (Event->ProcessId != 0 && Event->ProcessId <= MAXDWORD)
        {
            return static_cast<DWORD>(Event->ProcessId);
        }
        if (Event->EventProcessId != 0)
        {
            return Event->EventProcessId;
        }
        if (Event->TargetPid != 0 && Event->TargetPid <= MAXDWORD)
        {
            return static_cast<DWORD>(Event->TargetPid);
        }
        return 0;
    }

    DWORD PicTargetPid(_In_ const BKIPC_ETW_EVENT *Event)
    {
        if (Event != nullptr && Event->TargetPid != 0 && Event->TargetPid <= MAXDWORD)
        {
            return static_cast<DWORD>(Event->TargetPid);
        }
        return PicPrimaryPid(Event);
    }

    CONTROLLER_PIC_FACT PicBuildFact(_In_ const BKIPC_ETW_EVENT *Event)
    {
        CONTROLLER_PIC_FACT fact{};
        fact.ProcessId = PicPrimaryPid(Event);
        fact.ThreadId = (Event->HookArgCount > 0 && Event->HookArgs[0] <= MAXDWORD)
                            ? static_cast<DWORD>(Event->HookArgs[0])
                            : (Event->EventThreadId != 0 ? Event->EventThreadId
                                                         : static_cast<DWORD>(Event->ThreadId & 0xFFFFFFFFull));
        fact.LastTick = GetTickCount64();
        fact.ReturnPc = Event->OriginAddress != 0 ? Event->OriginAddress : Event->StartAddress;
        if (fact.ReturnPc == 0)
        {
            fact.ReturnPc = Event->HookArgCount > 0 ? Event->HookArgs[0] : 0;
        }
        fact.StackPointer = Event->HookArgCount > 3 ? Event->HookArgs[3] : 0;
        fact.Protect = Event->StartRegionProtect;
        if (Event->HookArgCount > 1)
        {
            fact.AllocationBase = Event->HookArgs[1];
        }
        if (Event->HookArgCount > 2)
        {
            fact.RegionSize = Event->HookArgs[2];
        }
        return fact;
    }

    bool PicLookupRecentFact(_In_ DWORD ProcessId, _Out_ CONTROLLER_PIC_FACT *Fact)
    {
        if (ProcessId == 0 || Fact == nullptr)
        {
            return false;
        }

        bool found = false;
        CONTROLLER_PIC_FACT best{};
        const ULONGLONG now = GetTickCount64();

        AcquireSRWLockShared(&g_PicFactsLock);
        for (const auto &slot : g_PicFacts)
        {
            if (slot.ProcessId != ProcessId || slot.LastTick == 0 || now < slot.LastTick ||
                now - slot.LastTick > kPicCorrelationWindowMs)
            {
                continue;
            }
            if (!found || slot.LastTick > best.LastTick)
            {
                best = slot;
                found = true;
            }
        }
        ReleaseSRWLockShared(&g_PicFactsLock);

        if (found)
        {
            *Fact = best;
        }
        return found;
    }

    void PicAppendReason(_Inout_ BKIPC_ETW_EVENT *Event, _In_ const CONTROLLER_PIC_FACT &Fact)
    {
        WCHAR suffix[256]{};
        size_t reasonLen = 0;
        const ULONGLONG now = GetTickCount64();
        const ULONGLONG ageMs = (now >= Fact.LastTick) ? (now - Fact.LastTick) : 0;

        (void)StringCchPrintfW(
            suffix, RTL_NUMBER_OF(suffix),
            L"; pic.directSyscall pc=0x%llX ageMs=%llu protect=0x%X allocationBase=0x%llX regionSize=0x%llX count=%lu",
            static_cast<unsigned long long>(Fact.ReturnPc), static_cast<unsigned long long>(ageMs),
            static_cast<unsigned int>(Fact.Protect), static_cast<unsigned long long>(Fact.AllocationBase),
            static_cast<unsigned long long>(Fact.RegionSize), static_cast<unsigned long>(Fact.Count));

        if (SUCCEEDED(StringCchLengthW(Event->Reason, RTL_NUMBER_OF(Event->Reason), &reasonLen)) && reasonLen != 0)
        {
            (void)StringCchCatW(Event->Reason, RTL_NUMBER_OF(Event->Reason), suffix);
        }
        else
        {
            (void)StringCchCopyW(Event->Reason, RTL_NUMBER_OF(Event->Reason), suffix + 2);
        }
    }

    void PicPromote(_Inout_ BKIPC_ETW_EVENT *Event, _In_z_ PCSTR DetectionName, _In_ UINT32 Severity,
                    _In_ const CONTROLLER_PIC_FACT &Fact)
    {
        (void)StringCchCopyA(Event->DetectionName, RTL_NUMBER_OF(Event->DetectionName), DetectionName);
        if (Event->Severity < Severity)
        {
            Event->Severity = Severity;
        }
        Event->Reserved2 = 0;
        PicAppendReason(Event, Fact);
    }

    bool PicDetectionContains(_In_ const BKIPC_ETW_EVENT *Event, _In_z_ PCSTR Text)
    {
        return ControllerAsciiContainsInsensitive(Event->DetectionName, Text) ||
               ControllerAsciiContainsInsensitive(Event->Operation, Text) ||
               ControllerAsciiContainsInsensitive(Event->ClassName, Text);
    }
} // namespace

VOID ControllerPicCorrelationObserve(_In_ const BKIPC_ETW_EVENT *Event)
{
    if (!PicEventIsDirectSyscall(Event))
    {
        return;
    }

    CONTROLLER_PIC_FACT fact = PicBuildFact(Event);
    if (fact.ProcessId == 0 || fact.ReturnPc == 0)
    {
        return;
    }

    AcquireSRWLockExclusive(&g_PicFactsLock);
    for (auto &slot : g_PicFacts)
    {
        if (slot.ProcessId == fact.ProcessId)
        {
            fact.Count = slot.Count + 1u;
            slot = fact;
            ReleaseSRWLockExclusive(&g_PicFactsLock);
            return;
        }
    }

    const LONG index = InterlockedIncrement(&g_PicNextSlot) & (kPicFactSlots - 1u);
    fact.Count = 1u;
    g_PicFacts[index] = fact;
    ReleaseSRWLockExclusive(&g_PicFactsLock);
}

VOID ControllerPicCorrelationApply(_Inout_ BKIPC_ETW_EVENT *Event)
{
    if (Event == nullptr)
    {
        return;
    }

    ControllerPicCorrelationObserve(Event);
    if (PicEventIsDirectSyscall(Event) ||
        ControllerAsciiEqualsInsensitive(Event->DetectionName, "BK_INSTRUMENTATION") ||
        (Event->Reserved2 & BKIPC_ETW_TRAIT_BLACKBIRD_OWN) != 0)
    {
        return;
    }

    CONTROLLER_PIC_FACT fact{};
    DWORD pid = PicPrimaryPid(Event);
    if (!PicLookupRecentFact(pid, &fact))
    {
        DWORD targetPid = PicTargetPid(Event);
        if (targetPid == pid || !PicLookupRecentFact(targetPid, &fact))
        {
            return;
        }
    }

    UINT32 traits = ControllerComputeEtwDetectionTraits(*Event);
    const bool memoryStaging = (traits & (BKIPC_ETW_TRAIT_MEMORY_ALLOC_RW | BKIPC_ETW_TRAIT_MEMORY_WRITE_VM |
                                          BKIPC_ETW_TRAIT_MEMORY_PROTECT_RX)) != 0;
    const bool remoteExecution = (traits & BKIPC_ETW_TRAIT_REMOTE_EXECUTION) != 0;
    const bool credentialAccess = (traits & BKIPC_ETW_TRAIT_CREDENTIAL_ACCESS) != 0;
    const bool imageTamper = (traits & BKIPC_ETW_TRAIT_IMAGE_TAMPER) != 0 || PicDetectionContains(Event, "HOLLOW") ||
                             PicDetectionContains(Event, "MANUAL_MAP") ||
                             PicDetectionContains(Event, "NON_IMAGE_EXECUTABLE_REGION");
    const bool antiAnalysis = PicDetectionContains(Event, "PROCESS_RECON") ||
                              ControllerAsciiEqualsInsensitive(Event->Operation, "NtQueryInformationProcess") ||
                              ControllerAsciiEqualsInsensitive(Event->Operation, "NtQuerySystemInformation") ||
                              ControllerAsciiEqualsInsensitive(Event->Operation, "NtSetInformationThread");

    if (credentialAccess)
    {
        PicPromote(Event, "DIRECT_SYSCALL_CREDENTIAL_ACCESS", 8u, fact);
    }
    else if (imageTamper)
    {
        PicPromote(Event, "PIC_CONFIRMED_MANUAL_MAP_OR_HOLLOWING", 8u, fact);
    }
    else if (remoteExecution)
    {
        PicPromote(Event, "DIRECT_SYSCALL_REMOTE_EXECUTION_CHAIN", 7u, fact);
    }
    else if (memoryStaging)
    {
        const bool remoteTarget =
            Event->TargetPid != 0 && Event->ProcessId != 0 && Event->TargetPid != Event->ProcessId;
        PicPromote(Event, "DIRECT_SYSCALL_SHELLCODE_STAGING", remoteTarget ? 8u : 7u, fact);
    }
    else if (antiAnalysis)
    {
        PicPromote(Event, "DIRECT_SYSCALL_ANTI_ANALYSIS_CLUSTER", 6u, fact);
    }
}

VOID ControllerPicCorrelationReset(VOID)
{
    AcquireSRWLockExclusive(&g_PicFactsLock);
    ZeroMemory(g_PicFacts, sizeof(g_PicFacts));
    InterlockedExchange(&g_PicNextSlot, -1);
    ReleaseSRWLockExclusive(&g_PicFactsLock);
}
