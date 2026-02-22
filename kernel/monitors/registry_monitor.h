#ifndef STINGER_REGISTRY_MONITOR_H
#define STINGER_REGISTRY_MONITOR_H

#include <ntddk.h>

NTSTATUS
STINGERRegistryMonitorInitialize(
    _In_ PDRIVER_OBJECT DriverObject
);

VOID
STINGERRegistryMonitorUninitialize(
    VOID
);

#endif
