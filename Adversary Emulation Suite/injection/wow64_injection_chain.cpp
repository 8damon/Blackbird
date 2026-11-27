#include "..\common\bkaes_sample.h"

int RunWow64InjectionChain() {
#if !defined(_M_IX86)
  BkaesPrint("[SKIP] WOW64 injection chain requires the x86 AES build\n");
  return 2;
#else
  BOOL wow64 = FALSE;
  IsWow64Process(GetCurrentProcess(), &wow64);
  BkaesPrint("[INFO] WOW64 process=%u\n", wow64 ? 1u : 0u);
  return RunInjectionChainComplete();
#endif
}
