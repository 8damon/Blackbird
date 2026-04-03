#ifndef BLACKBIRD_EVENT_PRINTER_H
#define BLACKBIRD_EVENT_PRINTER_H

#include <windows.h>
#include "..\..\abi\blackbird_ioctl.h"

void BLACKBIRDEventPrinterPrintRecord(const BLACKBIRD_EVENT_RECORD *rec);

#endif
