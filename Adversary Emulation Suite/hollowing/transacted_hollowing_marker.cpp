#include "..\common\bkaes_sample.h"

using CreateTransactionFn = HANDLE(WINAPI *)(LPSECURITY_ATTRIBUTES, LPGUID,
                                             DWORD, DWORD, DWORD, DWORD,
                                             LPWSTR);
using RollbackTransactionFn = BOOL(WINAPI *)(HANDLE);
using NtUnmapViewOfSectionFn = NTSTATUS(NTAPI *)(HANDLE, PVOID);

static void BkaesTouchTransactedFileMarker() {
  HMODULE ktmw32 = LoadLibraryW(L"ktmw32.dll");
  auto createTransaction =
      ktmw32 != nullptr
          ? (CreateTransactionFn)GetProcAddress(ktmw32, "CreateTransaction")
          : nullptr;
  auto rollbackTransaction =
      ktmw32 != nullptr
          ? (RollbackTransactionFn)GetProcAddress(ktmw32, "RollbackTransaction")
          : nullptr;
  HANDLE tx = nullptr;
  HANDLE file = INVALID_HANDLE_VALUE;
  std::wstring path = BkaesTempPath(L"bkaes-transacted-hollowing-marker.tmp");
  BYTE imageLike[512] = {};
  DWORD written = 0;

  imageLike[0] = 'M';
  imageLike[1] = 'Z';
  imageLike[0x3C] = 0x80;
  imageLike[0x80] = 'P';
  imageLike[0x81] = 'E';
  for (size_t i = 0x90; i < sizeof(imageLike); ++i) {
    imageLike[i] = (BYTE)((i * 73u) ^ 0xA5u);
  }

  if (createTransaction != nullptr) {
    tx = createTransaction(nullptr, nullptr, 0, 0, 0, 0, nullptr);
  }
  if (tx != nullptr && tx != INVALID_HANDLE_VALUE) {
    file = CreateFileTransactedW(
        path.c_str(), GENERIC_READ | GENERIC_WRITE | DELETE, 0, nullptr,
        CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE,
        nullptr, tx, nullptr, nullptr);
    if (file != INVALID_HANDLE_VALUE) {
      WriteFile(file, imageLike, sizeof(imageLike), &written, nullptr);
      CloseHandle(file);
    }
    if (rollbackTransaction != nullptr) {
      rollbackTransaction(tx);
    }
    CloseHandle(tx);
  } else {
    file = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE | DELETE, 0,
                       nullptr, CREATE_ALWAYS,
                       FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE,
                       nullptr);
    if (file != INVALID_HANDLE_VALUE) {
      WriteFile(file, imageLike, sizeof(imageLike), &written, nullptr);
      CloseHandle(file);
      DeleteFileW(path.c_str());
    }
  }

  if (ktmw32 != nullptr) {
    FreeLibrary(ktmw32);
  }
}

int RunTransactedHollowingMarker() {
  PROCESS_INFORMATION child = {};
  HANDLE process = nullptr;
  PVOID remote = nullptr;
  SIZE_T written = 0;
  DWORD oldProtect = 0;
  const SIZE_T regionSize = 0x20000;
  const SIZE_T stubOffset = 0x200;
  BYTE payload[4096] = {};
  CONTEXT context = {};
  bool contextSet = false;

  BkaesTouchTransactedFileMarker();

  if (!BkaesLaunchSelfChild(&child, CREATE_SUSPENDED | CREATE_NO_WINDOW)) {
    BkaesPrint("[FAIL] transacted hollowing child create err=%lu\n",
               GetLastError());
    return 1;
  }

  process = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
                            PROCESS_VM_READ | PROCESS_CREATE_THREAD |
                            PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE,
                        FALSE, child.dwProcessId);
  if (process == nullptr) {
    BkaesCleanupProcess(&child);
    return 1;
  }

  payload[0] = 'M';
  payload[1] = 'Z';
  payload[0x3C] = 0x80;
  payload[0x80] = 'P';
  payload[0x81] = 'E';
  payload[stubOffset] = 0xEB;
  payload[stubOffset + 1] = 0xFE;
  for (SIZE_T i = 0x90; i < sizeof(payload); ++i) {
    if (i != stubOffset && i != stubOffset + 1) {
      payload[i] = (BYTE)((i * 41u) ^ (i >> 1) ^ 0x3Du);
    }
  }

  remote = VirtualAllocEx(process, nullptr, regionSize,
                          MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (remote != nullptr &&
      WriteProcessMemory(process, remote, payload, sizeof(payload), &written) &&
      written == sizeof(payload) &&
      VirtualProtectEx(process, remote, regionSize, PAGE_EXECUTE_READ,
                       &oldProtect)) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    auto ntUnmapViewOfSection = ntdll != nullptr
                                    ? (NtUnmapViewOfSectionFn)GetProcAddress(
                                          ntdll, "NtUnmapViewOfSection")
                                    : nullptr;
    if (ntUnmapViewOfSection != nullptr) {
      ntUnmapViewOfSection(process, nullptr);
    }

    context.ContextFlags = CONTEXT_CONTROL;
    if (GetThreadContext(child.hThread, &context)) {
#if defined(_M_X64)
      context.Rip = (DWORD64)((BYTE *)remote + stubOffset);
#elif defined(_M_IX86)
      context.Eip = (DWORD)((BYTE *)remote + stubOffset);
#else
#error Unsupported architecture for transacted hollowing marker sample
#endif
      contextSet = SetThreadContext(child.hThread, &context) == TRUE;
    }
  }

  if (contextSet) {
    ResumeThread(child.hThread);
    WaitForSingleObject(child.hProcess, 500);
  }

  BkaesPrint("[OK] transacted hollowing marker targetPid=%lu remote=%p "
             "contextSet=%u\n",
             child.dwProcessId, remote, contextSet ? 1u : 0u);
  BkaesSettleTelemetry(3500);
  BkaesCleanupProcess(&child);
  if (remote != nullptr) {
    VirtualFreeEx(process, remote, 0, MEM_RELEASE);
  }
  if (process != nullptr) {
    CloseHandle(process);
  }
  return contextSet ? 0 : 1;
}
