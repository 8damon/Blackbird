#ifndef BK_EVENT_PRINTER_H
#define BK_EVENT_PRINTER_H

#include <windows.h>
#include "..\..\abi\blackbird_ioctl.h"

void BkevtPrinterPrintRecord(const BK_EVENT_RECORD *rec);

#endif
