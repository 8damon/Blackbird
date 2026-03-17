#pragma once

#include <Windows.h>

DWORD WINAPI BkRuntimeThreadProc(LPVOID);

void BkRuntimePrimeHooks() noexcept;

void BkRuntimeShutdown();

