#ifndef BK_ETW_PRINTER_H
#define BK_ETW_PRINTER_H

#include <windows.h>
#include <evntcons.h>

void BketwprPrintEtwRecord(_In_ PEVENT_RECORD Record, _In_z_ PCWSTR EventName);
void BketwprPrintThreatIntelRecord(_In_ PEVENT_RECORD Record, _In_opt_z_ PCWSTR EventName);
void BketwprPrimeProcessImagePath(_In_ ULONGLONG Pid, _In_opt_z_ PCWSTR ImagePath);
void BketwprPrimeProcessImageFromEtw(_In_ PEVENT_RECORD Record, _In_opt_z_ PCWSTR EventName);
void BketwprFlushEtwPrinterState(void);

#endif
