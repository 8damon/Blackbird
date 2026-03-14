#include "control/control_private.h"

WDFDEVICE g_ControlDevice = NULL;
FAST_MUTEX g_ClientListLock;
LIST_ENTRY g_ClientList;
LONG g_ClientCount = 0;
volatile LONG g_ControlInitialized = 0;
volatile LONG g_ControlShutdown = 0;
volatile LONG g_ControlTelemetryArmed = 0;
volatile LONG g_ControlQueueDropLogCounter = 0;
volatile LONG g_ControlTotalQueuedEvents = 0;
volatile LONG g_QueryImageInflight = 0;
volatile LONG g_QueryImageThrottleCounter = 0;
volatile LONG g_IoctlGetEventDeliverCounter = 0;
volatile LONG g_IoctlGetEventEmptyCounter = 0;
volatile LONG g_IoctlGetStatsCounter = 0;

