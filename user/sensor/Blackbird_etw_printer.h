#ifndef BLACKBIRD_ETW_PRINTER_H
#define BLACKBIRD_ETW_PRINTER_H

#include <windows.h>
#include <evntcons.h>

void BLACKBIRDPrintEtwRecord(_In_ PEVENT_RECORD Record, _In_z_ PCWSTR EventName);
void BLACKBIRDPrintThreatIntelRecord(_In_ PEVENT_RECORD Record, _In_opt_z_ PCWSTR EventName);
void BLACKBIRDPrimeProcessImagePath(_In_ ULONGLONG Pid, _In_opt_z_ PCWSTR ImagePath);
void BLACKBIRDPrimeProcessImageFromEtw(_In_ PEVENT_RECORD Record, _In_opt_z_ PCWSTR EventName);
void BLACKBIRDFlushEtwPrinterState(void);

#endif
