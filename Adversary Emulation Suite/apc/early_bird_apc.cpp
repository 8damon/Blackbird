#include "..\common\bkaes_sample.h"

int RunEarlyBirdApc() {
  PROCESS_INFORMATION child = {};
  HANDLE process = nullptr;
  HANDLE thread = nullptr;
  PVOID remote = nullptr;
  SIZE_T written = 0;
  DWORD oldProtect = 0;
  BYTE inertRoutine[] = {0xB8, 0x42, 0x00, 0x00, 0x00, 0xC3};
  NTSTATUS status = (NTSTATUS)0xC0000001;

  if (!BkaesLaunchSelfChild(&child, CREATE_SUSPENDED | CREATE_NO_WINDOW)) {
    BkaesPrint("[FAIL] early-bird child create err=%lu\n", GetLastError());
    return 1;
  }

  process = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
                            PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                        FALSE, child.dwProcessId);
  thread = OpenThread(THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME |
                          THREAD_QUERY_INFORMATION,
                      FALSE, child.dwThreadId);
  if (process != nullptr) {
    remote = VirtualAllocEx(process, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE,
                            PAGE_READWRITE);
  }
  if (remote != nullptr &&
      WriteProcessMemory(process, remote, inertRoutine, sizeof(inertRoutine),
                         &written) &&
      written == sizeof(inertRoutine) &&
      VirtualProtectEx(process, remote, 0x1000, PAGE_EXECUTE_READ,
                       &oldProtect)) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    auto ntQueueApcThread =
        ntdll != nullptr
            ? (NtQueueApcThreadFn)GetProcAddress(ntdll, "NtQueueApcThread")
            : nullptr;
    FlushInstructionCache(process, remote, sizeof(inertRoutine));
    if (ntQueueApcThread != nullptr && thread != nullptr) {
      status = ntQueueApcThread(thread, remote, nullptr, nullptr, nullptr);
    }
  }

  if (status >= 0) {
    ResumeThread(child.hThread);
    WaitForSingleObject(child.hProcess, 1200);
  }

  BkaesSettleTelemetry(2500);
  BkaesPrint("[OK] early-bird APC targetPid=%lu targetTid=%lu routine=%p "
             "status=0x%08X\n",
             child.dwProcessId, child.dwThreadId, remote, (unsigned)status);
  if (remote != nullptr && process != nullptr) {
    VirtualFreeEx(process, remote, 0, MEM_RELEASE);
  }
  if (thread != nullptr) {
    CloseHandle(thread);
  }
  if (process != nullptr) {
    CloseHandle(process);
  }
  BkaesCleanupProcess(&child);
  return status >= 0 ? 0 : 1;
}
