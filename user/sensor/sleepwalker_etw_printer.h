#ifndef SLEEPWALKER_ETW_PRINTER_H
#define SLEEPWALKER_ETW_PRINTER_H

#include <windows.h>
#include <evntcons.h>

void SLEEPWALKERPrintEtwRecord(_In_ PEVENT_RECORD Record, _In_z_ PCWSTR EventName);
void SLEEPWALKERPrintThreatIntelRecord(_In_ PEVENT_RECORD Record, _In_opt_z_ PCWSTR EventName);
void SLEEPWALKERPrimeProcessImagePath(_In_ ULONGLONG Pid, _In_opt_z_ PCWSTR ImagePath);
void SLEEPWALKERPrimeProcessImageFromEtw(_In_ PEVENT_RECORD Record, _In_opt_z_ PCWSTR EventName);
void SLEEPWALKERFlushEtwPrinterState(void);

#endif
