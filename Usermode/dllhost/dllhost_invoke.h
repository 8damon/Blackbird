#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>

#include "dllhost_options.h"

namespace BK::DllHost
{
    DWORD InvokeConfiguredMode(HMODULE module, const Options &options) noexcept;
}
