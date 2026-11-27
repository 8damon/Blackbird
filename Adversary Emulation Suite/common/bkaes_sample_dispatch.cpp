#include "bkaes_sample.h"

int wmain(int argc, wchar_t **argv) {
  int child = BkaesMaybeRunChildMode(argc, argv);
  if (child != INT_MIN) {
    return child;
  }

#if defined(BKAES_SAMPLE_DIRECT_SYSCALL_HANDLE)
  return RunDirectSyscallHandle();
#elif defined(BKAES_SAMPLE_DIRECT_SYSCALL_STACK_TF)
  return RunDirectSyscallStackTf();
#elif defined(BKAES_SAMPLE_NT_STUB_INTEGRITY_CHECK)
  return RunNtStubIntegrityCheck();
#elif defined(BKAES_SAMPLE_INJECTION_CHAIN_COMPLETE)
  return RunInjectionChainComplete();
#elif defined(BKAES_SAMPLE_PE_INJECTION_WRITE)
  return RunPeInjectionWrite();
#elif defined(BKAES_SAMPLE_SECTION_MAP_EXECUTE)
  return RunSectionMapExecute();
#elif defined(BKAES_SAMPLE_HOLLOWING_MARK_CHAIN)
  return RunHollowingMarkChain();
#elif defined(BKAES_SAMPLE_REMOTE_APC_QUEUE)
  return RunRemoteApcQueue();
#elif defined(BKAES_SAMPLE_REMOTE_APC_LOADLIBRARY)
  return RunRemoteApcLoadLibrary();
#elif defined(BKAES_SAMPLE_CONTEXT_HIJACK_TF)
  return RunContextHijackTf();
#elif defined(BKAES_SAMPLE_LOADLIBRARY_REMOTE_THREAD)
  return RunLoadLibraryRemoteThread();
#elif defined(BKAES_SAMPLE_SETWINDOWS_HOOKEX)
  return RunSetWindowsHookEx(argc, argv);
#elif defined(BKAES_SAMPLE_SETWINEVENT_HOOK)
  return RunSetWinEventHook(argc, argv);
#elif defined(BKAES_SAMPLE_GUI_HOOK_TARGET)
  return RunGuiHookTarget(argc, argv);
#elif defined(BKAES_SAMPLE_DIRECT_SYSCALL_INJECTION_CHAIN)
  return RunDirectSyscallInjectionChain();
#elif defined(BKAES_SAMPLE_WOW64_INJECTION_CHAIN)
  return RunWow64InjectionChain();
#elif defined(BKAES_SAMPLE_EVASION_INJECTION_CHAIN)
  return RunEvasionInjectionChain();
#elif defined(BKAES_SAMPLE_LOADLIBRARY_MODULE_NOTIFY)
  return RunLoadLibraryModuleNotify();
#elif defined(BKAES_SAMPLE_EARLY_BIRD_APC)
  return RunEarlyBirdApc();
#elif defined(BKAES_SAMPLE_TRANSACTED_HOLLOWING_MARKER)
  return RunTransactedHollowingMarker();
#elif defined(BKAES_SAMPLE_PPID_SPOOF)
  return RunPpidSpoof();
#elif defined(BKAES_SAMPLE_POWERSHELL_CMDLINES)
  return RunPowerShellCmdlines();
#elif defined(BKAES_SAMPLE_LOLBIN_CMDLINES)
  return RunLolbinCmdlines();
#elif defined(BKAES_SAMPLE_REGISTRY_PERSISTENCE_HKCU)
  return RunRegistryPersistenceHkcu();
#elif defined(BKAES_SAMPLE_REGISTRY_RECON)
  return RunRegistryRecon();
#elif defined(BKAES_SAMPLE_EDR_AV_PRODUCT_PROBES)
  return RunEdrAvProductProbes();
#elif defined(BKAES_SAMPLE_SECURITY_PRODUCT_ENTERPRISE_GEO_PROBES)
  return RunSecurityProductEnterpriseGeoProbes();
#elif defined(BKAES_SAMPLE_DLL_LOAD_SURFACE)
  return RunDllLoadSurface();
#elif defined(BKAES_SAMPLE_IMAGE_LOAD_DOUBLE_EXTENSION)
  return RunImageLoadDoubleExtension();
#elif defined(BKAES_SAMPLE_ANTI_DEBUG_VM_QUERIES)
  return RunAntiDebugVmQueries();
#elif defined(BKAES_SAMPLE_DYNAMIC_FUNCTION_TABLE)
  return RunDynamicFunctionTable();
#elif defined(BKAES_SAMPLE_MEMORY_FLIPS_ENTROPY)
  return RunMemoryFlipsEntropy();
#elif defined(BKAES_SAMPLE_GUARD_ORDERED_JIT)
  return RunGuardOrderedJit();
#elif defined(BKAES_SAMPLE_XOR_ENTROPY_CYCLE)
  return RunXorEntropyCycle();
#elif defined(BKAES_SAMPLE_NETWORK_PATTERNS)
  return RunNetworkPatterns();
#elif defined(BKAES_SAMPLE_BEACON_LOOPBACK_PATTERN)
  return RunBeaconLoopbackPattern();
#elif defined(BKAES_SAMPLE_COM_WMI_ETW_JOB)
  return RunComWmiEtwJob();
#elif defined(BKAES_SAMPLE_SENSITIVE_CREDENTIAL_HANDLES)
  return RunSensitiveCredentialHandles(argc, argv);
#elif defined(BKAES_SAMPLE_KERBEROS_RECON_EXTENDED)
  return RunKerberosReconExtended();
#elif defined(BKAES_SAMPLE_LPE_SURFACE)
  return RunLpeSurface();
#elif defined(BKAES_SAMPLE_TARGET_NONZERO_EXIT)
  BkaesPrint("[OK] returning non-zero status for launch lifecycle detection\n");
  BkaesSettleTelemetry(1000);
  return 37;
#elif defined(BKAES_SAMPLE_TARGET_EXCEPTION)
  RaiseException(0xE0424B42, 0, 0, nullptr);
  return 1;
#elif defined(BKAES_SAMPLE_FUZZ_NTAPI_QUERIES)
  return RunFuzzNtapiQueries();
#elif defined(BKAES_SAMPLE_FUZZ_REGISTRY_PATHS)
  return RunFuzzRegistryPaths();
#elif defined(BKAES_SAMPLE_FUZZ_MODULE_LOADS)
  return RunFuzzModuleLoads();
#elif defined(BKAES_SAMPLE_OK_FILE_REGISTRY)
  return RunOkFileRegistry();
#elif defined(BKAES_SAMPLE_OK_MEMORY_PROCESS)
  return RunOkMemoryProcess();
#elif defined(BKAES_SAMPLE_OK_NETWORK_LOOPBACK)
  return RunOkNetworkLoopback();
#elif defined(BKAES_SAMPLE_OK_DOCUMENT_WORKFLOW)
  return RunOkDocumentWorkflow();
#elif defined(BKAES_SAMPLE_OK_SYSTEM_INVENTORY)
  return RunOkSystemInventory();
#elif defined(BKAES_SAMPLE_OK_COM_LOGGING_JOB)
  return RunOkComLoggingJob();
#elif defined(BKAES_SAMPLE_OK_SYSTEM_DLL_LOADS)
  return RunOkSystemDllLoads();
#elif defined(BKAES_SAMPLE_OK_LOCALHOST_SERVICE)
  return RunOkLocalhostService();
#else
  BkaesPrint("[FAIL] no BKAES_SAMPLE_* define supplied\n");
  return 1;
#endif
}
