#include "tests/blackbird_ioctl_test_internal.h"

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "version.lib")

ETW_CAPTURE *g_ActiveEtwCapture = NULL;
