#ifndef SLEEPWALKER_REGISTRY_MONITOR_H
#define SLEEPWALKER_REGISTRY_MONITOR_H

#include <ntddk.h>

NTSTATUS
SLEEPWALKERRegistryMonitorInitialize(_In_ PDRIVER_OBJECT DriverObject);

VOID SLEEPWALKERRegistryMonitorUninitialize(VOID);

BOOLEAN
SLEEPWALKERRegistryMonitorSelfCheck(VOID);

#endif
