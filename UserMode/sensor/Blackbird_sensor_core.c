#include "core/blackbird_sensor_core_internal.h"

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "tdh.lib")

BLACKBIRDSC_API const GUID BLACKBIRDSC_PROVIDER_GUID_BLACKBIRD = {
    0xd6c73f8a, 0x6ad8, 0x4f4b, {0xa3, 0x63, 0x3d, 0x2f, 0xa3, 0x1c, 0xd0, 0xe2}};
BLACKBIRDSC_API const GUID BLACKBIRDSC_PROVIDER_GUID_TI = {
    0xf4e1897c, 0xbb5d, 0x5668, {0xf1, 0xd8, 0x04, 0x0f, 0x4d, 0x8d, 0xd3, 0x44}};
BLACKBIRDSC_API const GUID BLACKBIRDSC_PROVIDER_GUID_KERNEL_NETWORK = {
    0x7dd42a49, 0x5329, 0x4832, {0x8d, 0xfd, 0x43, 0xd9, 0x79, 0x15, 0x3a, 0x88}};

volatile LONG g_BlackbirdProtocolMode = BLACKBIRDSC_PROTOCOL_SERVICE;
WCHAR g_BlackbirdPipeName[MAX_PATH] = BLACKBIRD_IPC_PIPE_NAME;
DWORD g_BlackbirdPipeTimeoutMs = 3000;
volatile LONG g_BlackbirdIpcSequence = 1;
volatile LONG g_BlackbirdBrokerCapabilities = 0;
volatile LONG g_BlackbirdBrokerThreatIntelEnabled = 0;
volatile LONG g_BlackbirdLastTiEnableError = 0;
volatile LONG g_BlackbirdLastSharedRingError = ERROR_NOT_FOUND;
SRWLOCK g_BlackbirdProtocolLock = SRWLOCK_INIT;
