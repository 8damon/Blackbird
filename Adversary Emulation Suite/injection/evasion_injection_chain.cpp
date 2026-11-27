#include "..\common\bkaes_sample.h"

static void BkaesIssueEvasionQueries() {
  HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
  auto ntQueryInformationProcess =
      ntdll != nullptr ? (NtQueryInformationProcessFn)GetProcAddress(
                             ntdll, "NtQueryInformationProcess")
                       : nullptr;
  auto ntQuerySystemInformation =
      ntdll != nullptr ? (NtQuerySystemInformationFn)GetProcAddress(
                             ntdll, "NtQuerySystemInformation")
                       : nullptr;
  ULONG ret = 0;
  ULONG value = 0;
  BYTE buffer[512] = {};

  if (ntQueryInformationProcess != nullptr) {
    ntQueryInformationProcess(GetCurrentProcess(), (PROCESSINFOCLASS)7, &value,
                              sizeof(value), &ret);
    ntQueryInformationProcess(GetCurrentProcess(), (PROCESSINFOCLASS)30, &value,
                              sizeof(value), &ret);
    ntQueryInformationProcess(GetCurrentProcess(), (PROCESSINFOCLASS)31, &value,
                              sizeof(value), &ret);
  }
  if (ntQuerySystemInformation != nullptr) {
    ntQuerySystemInformation((SYSTEM_INFORMATION_CLASS)35, buffer,
                             sizeof(buffer), &ret);
    ntQuerySystemInformation((SYSTEM_INFORMATION_CLASS)76, buffer,
                             sizeof(buffer), &ret);
  }

  GetSystemFirmwareTable('RSMB', 0, buffer, sizeof(buffer));
  GetFileAttributesW(L"C:\\Windows\\System32\\drivers\\vmmouse.sys");
  GetFileAttributesW(L"C:\\Windows\\System32\\drivers\\VBoxMouse.sys");
}

int RunEvasionInjectionChain() {
  BkaesIssueEvasionQueries();
  int result = RunInjectionChainComplete();
  BkaesPrint("[OK] evasion query plus injection chain result=%d\n", result);
  return result;
}
