#ifndef BLACKBIRD_REGISTRY_MONITOR_H
#define BLACKBIRD_REGISTRY_MONITOR_H

#include <ntddk.h>

NTSTATUS
BLACKBIRDRegistryMonitorInitialize(_In_ PDRIVER_OBJECT DriverObject);

VOID BLACKBIRDRegistryMonitorUninitialize(VOID);

BOOLEAN
BLACKBIRDRegistryMonitorSelfCheck(VOID);

#endif
