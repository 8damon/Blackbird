#include "ns_launcher.h"

BOOL ControllerStartNetService(_In_ HANDLE DriverHandle)
{
    UNREFERENCED_PARAMETER(DriverHandle);
    ControllerLog("[NODE][INFO] optional node networking is not included in this build\n");
    return FALSE;
}

VOID ControllerStopNetService(VOID)
{
}

VOID ControllerRefreshNetSvcDriverHandle(_In_ HANDLE DriverHandle, _In_z_ PCSTR Reason)
{
    UNREFERENCED_PARAMETER(DriverHandle);
    UNREFERENCED_PARAMETER(Reason);
}
