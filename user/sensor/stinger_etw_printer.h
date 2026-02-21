#ifndef STINGER_ETW_PRINTER_H
#define STINGER_ETW_PRINTER_H

#include <windows.h>
#include <evntcons.h>

void STINGERPrintEtwRecord(_In_ PEVENT_RECORD Record, _In_z_ PCWSTR EventName);

#endif
