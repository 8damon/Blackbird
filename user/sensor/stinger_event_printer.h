#ifndef STINGER_EVENT_PRINTER_H
#define STINGER_EVENT_PRINTER_H

#include <windows.h>
#include "..\..\abi\stinger_ioctl.h"

void STINGEREventPrinterPrintRecord(const STINGER_EVENT_RECORD* rec);

#endif
