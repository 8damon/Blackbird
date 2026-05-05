#ifndef BK_CONTROLLER_NET_SERVICE_LAUNCHER_H
#define BK_CONTROLLER_NET_SERVICE_LAUNCHER_H

#include "../../controller_private.h"

BOOL ControllerStartNetService(_In_ HANDLE DriverHandle);
VOID ControllerStopNetService(VOID);
VOID ControllerRefreshNetSvcDriverHandle(_In_ HANDLE DriverHandle, _In_z_ PCSTR Reason);

#endif
