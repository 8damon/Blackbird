#include "..\common\bkaes_sample.h"

int RunLoadLibraryModuleNotify() {
  std::wstring dllPath =
      BkaesJoinPath(BkaesSelfDirectory(), L"bb_unsigned_plugin.dll");
  HMODULE module = LoadLibraryW(dllPath.c_str());
  if (module == nullptr) {
    BkaesPrint("[FAIL] LoadLibrary module notify dll=%ls err=%lu\n",
               dllPath.c_str(), GetLastError());
    return 1;
  }

  FARPROC exportAddress = GetProcAddress(module, "BkaesUnsignedPluginTouch");
  BkaesSettleTelemetry(2500);
  BkaesPrint("[OK] LoadLibrary module notify dll=%ls module=%p export=%p\n",
             dllPath.c_str(), module, exportAddress);
  FreeLibrary(module);
  return 0;
}
