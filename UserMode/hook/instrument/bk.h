#pragma once
#ifndef BK_BLACKBIRD_VEH_H
#define BK_BLACKBIRD_VEH_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <cstdint>
#include <cstddef>
#ifndef BK_BLACKBIRD_API
#ifdef BK_BLACKBIRD_EXPORTS
#define BK_BLACKBIRD_API extern "C" __declspec(dllexport)
#elif defined(BK_BLACKBIRD_IMPORTS)
#define BK_BLACKBIRD_API extern "C" __declspec(dllimport)
#else
#define BK_BLACKBIRD_API extern "C"
#endif
#endif

namespace bk::BK
{
    inline constexpr std::size_t kMaxStackFrames = 64;
    inline constexpr std::size_t kMaxModuleName = 64;
    inline constexpr std::size_t kMaxExInfo = 4;

    struct Event final
    {
        DWORD exception_code{};
        DWORD exception_flags{};
        void *exception_address{};

        DWORD pid{};
        DWORD tid{};

        wchar_t module_basename_lower[kMaxModuleName]{};

        ULONG exception_info_count{};
        ULONG_PTR exception_info[kMaxExInfo]{};

        USHORT stack_frame_count{};
        void *stack[kMaxStackFrames]{};

        bool is_target_module{};
        bool is_memory_fault{};
        bool is_noncontinuable{};
    };

    using TelemetryFn = void (*)(const Event &evt, void *user) noexcept;
    using MemoryFaultHandlerFn = bool (*)(const Event &evt, EXCEPTION_POINTERS *ep, void *user) noexcept;

    struct TelemetryArguments final
    {
        const wchar_t *target_module_basename = nullptr;

        TelemetryFn low_noise_telemetry = nullptr;
        TelemetryFn high_noise_telemetry = nullptr;

        MemoryFaultHandlerFn memory_fault_handler = nullptr;

        void *user = nullptr;

        bool install_first = true;
        bool auto_promote = true;

        bool capture_stack = true;
        std::uint16_t stack_frames_to_skip = 3;
        std::uint16_t max_stack_frames = static_cast<std::uint16_t>(kMaxStackFrames);

        bool swallow_non_target_exceptions = false;
    };
}
using BkBlackbirdEvent = bk::BK::Event;
using BkBlackbirdTelemetryArguments = bk::BK::TelemetryArguments;
using BkBlackbirdTelemetryFn = bk::BK::TelemetryFn;
using BkBlackbirdMemoryFaultHandlerFn = bk::BK::MemoryFaultHandlerFn;
BK_BLACKBIRD_API PVOID BkRegisterVectoredExceptionHandler(BkBlackbirdTelemetryArguments *args) noexcept;
BK_BLACKBIRD_API BOOL BkPromoteVectoredExceptionHandlerToFront() noexcept;
BK_BLACKBIRD_API void BkUnregisterVectoredExceptionHandler() noexcept;
inline PVOID BkRegisterVectordExceptionHandler(BkBlackbirdTelemetryArguments *args) noexcept
{
    return BkRegisterVectoredExceptionHandler(args);
}

inline void BkUnregisterVectordExceptionHandler() noexcept
{
    BkUnregisterVectoredExceptionHandler();
}

#endif
