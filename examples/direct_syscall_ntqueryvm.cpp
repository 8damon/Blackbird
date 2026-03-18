#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <strsafe.h>

typedef NTSTATUS (NTAPI* BLACKBIRD_NT_QUERY_VIRTUAL_MEMORY_FN)(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress,
    _In_ ULONG MemoryInformationClass,
    _Out_writes_bytes_(MemoryInformationLength) PVOID MemoryInformation,
    _In_ SIZE_T MemoryInformationLength,
    _Out_opt_ PSIZE_T ReturnLength
);

typedef NTSTATUS (NTAPI* BLACKBIRD_NT_OPEN_PROCESS_FN)(
    _Out_ PHANDLE ProcessHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ PVOID ClientId
);

typedef struct _BLACKBIRD_CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} BLACKBIRD_CLIENT_ID;

#define BLACKBIRD_MEMORY_BASIC_INFORMATION_CLASS 0ul
#define BLACKBIRD_STATUS_SUCCESS ((NTSTATUS)0)

#if !defined(_M_X64)
int __cdecl
main(void)
{
    printf("direct_syscall_ntqueryvm example is x64-only\n");
    return 1;
}
#else

static BYTE g_SyscallStubQueryVm[16];
static BYTE g_SyscallStubOpenProcess[16];

static
BOOL
ScanStubForSsn(
    _In_reads_bytes_(StubBytes) const BYTE* Stub,
    _In_ size_t StubBytes,
    _Out_ DWORD* Ssn
)
{
    size_t i;
    size_t j;

    if (Stub == NULL || Ssn == NULL || StubBytes < 8) {
        return FALSE;
    }

    for (i = 0; i + 4 < StubBytes; ++i) {
        if (Stub[i] == 0xB8) {
            DWORD value;
            (void)memcpy(&value, &Stub[i + 1], sizeof(value));
            for (j = i + 5; j + 1 < StubBytes && j < (i + 32); ++j) {
                if (Stub[j] == 0x0F && Stub[j + 1] == 0x05) {
                    *Ssn = value;
                    return TRUE;
                }
            }
        }
    }

    return FALSE;
}

static
const BYTE*
TryResolveJumpTarget(
    _In_reads_bytes_(16) const BYTE* Stub
)
{
    if (Stub == NULL) {
        return NULL;
    }

    if (Stub[0] == 0xE9) {
        int32_t rel32;
        (void)memcpy(&rel32, &Stub[1], sizeof(rel32));
        return Stub + 5 + rel32;
    }
    if (Stub[0] == 0xEB) {
        int8_t rel8 = (int8_t)Stub[1];
        return Stub + 2 + rel8;
    }
    if (Stub[0] == 0xFF && Stub[1] == 0x25) {
        int32_t disp32;
        const BYTE* tablePtr;
        const BYTE* target;
        (void)memcpy(&disp32, &Stub[2], sizeof(disp32));
        tablePtr = Stub + 6 + disp32;
        (void)memcpy(&target, tablePtr, sizeof(target));
        return target;
    }
    if (Stub[0] == 0x48 && Stub[1] == 0xB8 && Stub[10] == 0xFF && Stub[11] == 0xE0) {
        const BYTE* target;
        (void)memcpy(&target, &Stub[2], sizeof(target));
        return target;
    }

    return NULL;
}

static
BOOL
ExtractSsnFromNtStub(
    _In_reads_bytes_(StubBytes) const BYTE* Stub,
    _In_ size_t StubBytes,
    _Out_ DWORD* Ssn
)
{
    const BYTE* candidates[3];
    size_t count = 0;
    size_t i;

    if (Stub == NULL || Ssn == NULL || StubBytes < 8) {
        return FALSE;
    }

    candidates[count++] = Stub;
    {
        const BYTE* jump1 = TryResolveJumpTarget(Stub);
        if (jump1 != NULL && count < RTL_NUMBER_OF(candidates)) {
            candidates[count++] = jump1;
            {
                const BYTE* jump2 = TryResolveJumpTarget(jump1);
                if (jump2 != NULL && count < RTL_NUMBER_OF(candidates)) {
                    candidates[count++] = jump2;
                }
            }
        }
    }

    for (i = 0; i < count; ++i) {
        if (ScanStubForSsn(candidates[i], StubBytes, Ssn)) {
            return TRUE;
        }
    }

    return FALSE;
}

static
void
BuildSyscallStub(
    _Out_writes_(16) BYTE* Stub,
    _In_ DWORD Ssn
)
{
    Stub[0] = 0x4C; // mov r10, rcx
    Stub[1] = 0x8B;
    Stub[2] = 0xD1;
    Stub[3] = 0xB8; // mov eax, imm32
    (void)memcpy(&Stub[4], &Ssn, sizeof(Ssn));
    Stub[8] = 0x0F; // syscall
    Stub[9] = 0x05;
    Stub[10] = 0xC3; // ret
    Stub[11] = 0x90;
    Stub[12] = 0x90;
    Stub[13] = 0x90;
    Stub[14] = 0x90;
    Stub[15] = 0x90;
}

static
BOOL
LaunchChildProcess(
    _Out_ PROCESS_INFORMATION* Pi
)
{
    WCHAR selfPath[MAX_PATH];
    WCHAR commandLine[(MAX_PATH * 2) + 64];
    STARTUPINFOW si;

    if (Pi == NULL) {
        return FALSE;
    }
    ZeroMemory(Pi, sizeof(*Pi));

    if (GetModuleFileNameW(NULL, selfPath, RTL_NUMBER_OF(selfPath)) == 0) {
        return FALSE;
    }
    if (FAILED(StringCchPrintfW(commandLine, RTL_NUMBER_OF(commandLine), L"\"%ls\" --child-sleep", selfPath))) {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);

    return CreateProcessW(
        NULL,
        commandLine,
        NULL,
        NULL,
        FALSE,
        CREATE_NO_WINDOW,
        NULL,
        NULL,
        &si,
        Pi
    );
}

int __cdecl
main(
    int argc,
    char** argv
)
{
    PROCESS_INFORMATION childPi;
    DWORD preAttachDelayMs = 2500;
    DWORD targetPid = 0;
    HMODULE ntdll;
    BLACKBIRD_NT_QUERY_VIRTUAL_MEMORY_FN ntQueryVirtualMemory;
    BLACKBIRD_NT_OPEN_PROCESS_FN ntOpenProcess;
    DWORD ssnQueryVm = 0;
    DWORD ssnOpenProcess = 0;
    DWORD oldProtectQueryVm = 0;
    DWORD oldProtectOpenProcess = 0;
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T outLen = 0;
    NTSTATUS statusWinApi = BLACKBIRD_STATUS_SUCCESS;
    NTSTATUS statusDirect = BLACKBIRD_STATUS_SUCCESS;
    NTSTATUS statusOpenLegit = BLACKBIRD_STATUS_SUCCESS;
    NTSTATUS statusOpenDirect = BLACKBIRD_STATUS_SUCCESS;
    BLACKBIRD_NT_QUERY_VIRTUAL_MEMORY_FN directQueryVmCall;
    BLACKBIRD_NT_OPEN_PROCESS_FN directOpenProcessCall;

    ZeroMemory(&childPi, sizeof(childPi));

    if (argc >= 2 && _stricmp(argv[1], "--child-sleep") == 0) {
        Sleep(15000);
        return 0;
    }

    if (argc >= 2) {
        preAttachDelayMs = strtoul(argv[1], NULL, 10);
    }

    printf(
        "[*] pre-attach-wait=%lu ms single-shot=true\n",
        (unsigned long)preAttachDelayMs
    );
    if (preAttachDelayMs != 0) {
        Sleep(preAttachDelayMs);
    }

    ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll == NULL) {
        printf("GetModuleHandleW(ntdll.dll) failed err=%lu\n", GetLastError());
        return 1;
    }

    ntQueryVirtualMemory = (BLACKBIRD_NT_QUERY_VIRTUAL_MEMORY_FN)GetProcAddress(ntdll, "NtQueryVirtualMemory");
    if (ntQueryVirtualMemory == NULL) {
        printf("GetProcAddress(NtQueryVirtualMemory) failed err=%lu\n", GetLastError());
        return 1;
    }
    ntOpenProcess = (BLACKBIRD_NT_OPEN_PROCESS_FN)GetProcAddress(ntdll, "NtOpenProcess");
    if (ntOpenProcess == NULL) {
        printf("GetProcAddress(NtOpenProcess) failed err=%lu\n", GetLastError());
        return 1;
    }

    if (!ExtractSsnFromNtStub((const BYTE*)ntQueryVirtualMemory, 96, &ssnQueryVm)) {
        printf("Failed to extract SSN from NtQueryVirtualMemory stub\n");
        return 1;
    }
    if (!ExtractSsnFromNtStub((const BYTE*)ntOpenProcess, 96, &ssnOpenProcess)) {
        printf("Failed to extract SSN from NtOpenProcess stub\n");
        return 1;
    }

    if (!LaunchChildProcess(&childPi)) {
        printf("LaunchChildProcess failed err=%lu\n", GetLastError());
        return 1;
    }
    targetPid = childPi.dwProcessId;
    Sleep(150);

    BuildSyscallStub(g_SyscallStubQueryVm, ssnQueryVm);
    BuildSyscallStub(g_SyscallStubOpenProcess, ssnOpenProcess);

    if (!VirtualProtect(g_SyscallStubQueryVm, sizeof(g_SyscallStubQueryVm), PAGE_EXECUTE_READWRITE, &oldProtectQueryVm)) {
        printf("VirtualProtect(g_SyscallStubQueryVm) failed err=%lu\n", GetLastError());
        return 1;
    }
    if (!VirtualProtect(g_SyscallStubOpenProcess, sizeof(g_SyscallStubOpenProcess), PAGE_EXECUTE_READWRITE, &oldProtectOpenProcess)) {
        printf("VirtualProtect(g_SyscallStubOpenProcess) failed err=%lu\n", GetLastError());
        return 1;
    }

    directQueryVmCall = (BLACKBIRD_NT_QUERY_VIRTUAL_MEMORY_FN)(void*)g_SyscallStubQueryVm;
    directOpenProcessCall = (BLACKBIRD_NT_OPEN_PROCESS_FN)(void*)g_SyscallStubOpenProcess;

    {
        HANDLE opened = NULL;
        OBJECT_ATTRIBUTES oa;
        BLACKBIRD_CLIENT_ID cid;

        ZeroMemory(&mbi, sizeof(mbi));
        outLen = 0;
        statusWinApi = ntQueryVirtualMemory(
            GetCurrentProcess(),
            (PVOID)(ULONG_PTR)&main,
            BLACKBIRD_MEMORY_BASIC_INFORMATION_CLASS,
            &mbi,
            sizeof(mbi),
            &outLen
        );

        ZeroMemory(&mbi, sizeof(mbi));
        outLen = 0;
        statusDirect = directQueryVmCall(
            GetCurrentProcess(),
            (PVOID)(ULONG_PTR)&main,
            BLACKBIRD_MEMORY_BASIC_INFORMATION_CLASS,
            &mbi,
            sizeof(mbi),
            &outLen
        );

        InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
        cid.UniqueProcess = (HANDLE)(ULONG_PTR)targetPid;
        cid.UniqueThread = NULL;

        statusOpenLegit = ntOpenProcess(
            &opened,
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD,
            &oa,
            &cid
        );
        if (opened != NULL) {
            CloseHandle(opened);
            opened = NULL;
        }

        statusOpenDirect = directOpenProcessCall(
            &opened,
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD,
            &oa,
            &cid
        );
        if (opened != NULL) {
            CloseHandle(opened);
            opened = NULL;
        }

        printf(
            "[single] targetPid=%lu qvm{export=0x%08X direct=0x%08X ssn=0x%04X} open{export=0x%08X direct=0x%08X ssn=0x%04X}\n",
            (unsigned long)targetPid,
            (unsigned int)statusWinApi,
            (unsigned int)statusDirect,
            (unsigned int)(ssnQueryVm & 0xFFFF),
            (unsigned int)statusOpenLegit,
            (unsigned int)statusOpenDirect,
            (unsigned int)(ssnOpenProcess & 0xFFFF)
        );
    }

    (void)VirtualProtect(g_SyscallStubQueryVm, sizeof(g_SyscallStubQueryVm), oldProtectQueryVm, &oldProtectQueryVm);
    (void)VirtualProtect(g_SyscallStubOpenProcess, sizeof(g_SyscallStubOpenProcess), oldProtectOpenProcess, &oldProtectOpenProcess);

    if (childPi.hProcess != NULL) {
        (void)TerminateProcess(childPi.hProcess, 0);
        (void)WaitForSingleObject(childPi.hProcess, 2000);
        CloseHandle(childPi.hProcess);
        childPi.hProcess = NULL;
    }
    if (childPi.hThread != NULL) {
        CloseHandle(childPi.hThread);
        childPi.hThread = NULL;
    }

    if (statusWinApi >= 0 && statusDirect >= 0 && statusOpenLegit >= 0 && statusOpenDirect >= 0) {
        printf("[OK] single-shot completed (NtQueryVirtualMemory + NtOpenProcess(export/direct) against remote child)\n");
        return 0;
    }

    printf("[FAIL] at least one call path failed in final iteration\n");
    return 1;
}
#endif


