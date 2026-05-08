#include "runtime_private.h"

#include <memoryapi.h>

namespace BK_RUNTIME_INTERNAL
{
    namespace
    {
        using SetProcessValidCallTargetsFn = BOOL(WINAPI *)(HANDLE, PVOID, SIZE_T, ULONG, PCFG_CALL_TARGET_INFO);

#ifndef CFG_CALL_TARGET_VALID_XFG
#define CFG_CALL_TARGET_VALID_XFG 0x00000008
#endif

        volatile LONG g_CfgPolicyState = 0;
        std::uint32_t g_CfgPolicyFlags = 0;
        std::uint32_t g_CfgPolicyLastError = 0;
        volatile LONG g_SetCfgTargetsState = 0;
        SetProcessValidCallTargetsFn g_SetCfgTargets = nullptr;
        DWORD g_PageSize = 0;

        DWORD QueryPageSize() noexcept
        {
            DWORD cached = g_PageSize;
            if (cached != 0)
            {
                return cached;
            }

            SYSTEM_INFO info{};
            GetSystemInfo(&info);
            cached = info.dwPageSize != 0 ? info.dwPageSize : 0x1000u;
            g_PageSize = cached;
            return cached;
        }

        bool IsExecutableProtection(DWORD protect) noexcept
        {
            DWORD baseProtect = protect & 0xFFu;
            return baseProtect == PAGE_EXECUTE || baseProtect == PAGE_EXECUTE_READ ||
                   baseProtect == PAGE_EXECUTE_READWRITE || baseProtect == PAGE_EXECUTE_WRITECOPY;
        }

        SetProcessValidCallTargetsFn ResolveSetProcessValidCallTargets() noexcept
        {
            LONG state = InterlockedCompareExchange(&g_SetCfgTargetsState, 0, 0);
            if (state == 2)
            {
                return g_SetCfgTargets;
            }
            if (state == 1)
            {
                return nullptr;
            }

            HMODULE module = GetModuleHandleW(L"kernelbase.dll");
            if (module == nullptr)
            {
                module = GetModuleHandleW(L"kernel32.dll");
            }

            auto fn = module != nullptr
                          ? reinterpret_cast<SetProcessValidCallTargetsFn>(
                                GetProcAddress(module, "SetProcessValidCallTargets"))
                          : nullptr;
            g_SetCfgTargets = fn;
            InterlockedExchange(&g_SetCfgTargetsState, fn != nullptr ? 2 : 1);
            return fn;
        }

        bool ApplyCallTargetFlags(SetProcessValidCallTargetsFn fn, void *pageBase, SIZE_T pageSize,
                                  ULONG_PTR offset, ULONG_PTR flags) noexcept
        {
            CFG_CALL_TARGET_INFO info{};
            info.Offset = offset;
            info.Flags = flags;
            return fn(GetCurrentProcess(), pageBase, pageSize, 1, &info) != FALSE;
        }
    }

    Sr71ControlFlowPolicy QueryCurrentProcessControlFlowPolicy() noexcept
    {
        LONG state = InterlockedCompareExchange(&g_CfgPolicyState, 0, 0);
        if (state == 0)
        {
            PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY policy{};
            DWORD lastError = 0;
            bool ok = false;

            {
                BkSr71InternalScope scope;
                ok = GetProcessMitigationPolicy(GetCurrentProcess(), ProcessControlFlowGuardPolicy, &policy,
                                                sizeof(policy)) != FALSE;
                if (!ok)
                {
                    lastError = GetLastError();
                }
            }

            g_CfgPolicyFlags = ok ? policy.Flags : 0u;
            g_CfgPolicyLastError = ok ? 0u : lastError;
            InterlockedExchange(&g_CfgPolicyState, ok ? 2 : 1);
            state = ok ? 2 : 1;

            BkDbgLog("QueryCurrentProcessControlFlowPolicy: ok=%u flags=0x%08lX cfg=%u strict=%u xfg=%u audit=%u gle=%lu",
                     ok ? 1u : 0u, static_cast<unsigned long>(g_CfgPolicyFlags),
                     ok && policy.EnableControlFlowGuard ? 1u : 0u, ok && policy.StrictMode ? 1u : 0u,
                     ok && policy.EnableXfg ? 1u : 0u, ok && policy.EnableXfgAuditMode ? 1u : 0u,
                     static_cast<unsigned long>(lastError));
        }

        Sr71ControlFlowPolicy result{};
        result.QuerySucceeded = (state == 2);
        result.Flags = g_CfgPolicyFlags;
        result.LastError = g_CfgPolicyLastError;

        if (result.QuerySucceeded)
        {
            result.CfgEnabled = (g_CfgPolicyFlags & 0x1u) != 0;
            result.CfgStrictMode = (g_CfgPolicyFlags & 0x4u) != 0;
            result.XfgEnabled = (g_CfgPolicyFlags & 0x8u) != 0;
            result.XfgAuditMode = (g_CfgPolicyFlags & 0x10u) != 0;
        }
        return result;
    }

    bool RegisterControlFlowGuardCallTarget(void *targetAddress, Sr71CfgCallTargetMode mode, const char *tag) noexcept
    {
        if (targetAddress == nullptr)
        {
            return false;
        }

        Sr71ControlFlowPolicy policy = QueryCurrentProcessControlFlowPolicy();
        if (!policy.CfgEnabled)
        {
            return true;
        }

        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQuery(targetAddress, &mbi, sizeof(mbi)) != sizeof(mbi) || mbi.State != MEM_COMMIT ||
            !IsExecutableProtection(mbi.Protect))
        {
            BkRuntimeReportFault(BkRuntimeFaultCode::ControlFlowCallTargetRegisterFailed,
                                 reinterpret_cast<std::uint64_t>(targetAddress), 1);
            return false;
        }

        const bool imageTarget = (mbi.Type == MEM_IMAGE);
        const bool wantsXfg = mode == Sr71CfgCallTargetMode::CfgAndXfgWhenEnabled &&
                              (policy.XfgEnabled || policy.XfgAuditMode);
        const bool requiresXfg = mode == Sr71CfgCallTargetMode::CfgAndXfgWhenEnabled && policy.XfgEnabled;
        if (imageTarget && !wantsXfg)
        {
            return true;
        }

        SetProcessValidCallTargetsFn fn = ResolveSetProcessValidCallTargets();
        if (fn == nullptr)
        {
            BkRuntimeReportFault(BkRuntimeFaultCode::ControlFlowCallTargetRegisterFailed,
                                 reinterpret_cast<std::uint64_t>(targetAddress), 2);
            return false;
        }

        const DWORD pageSize = QueryPageSize();
        const auto address = reinterpret_cast<ULONG_PTR>(targetAddress);
        const auto pageBaseValue = address & ~static_cast<ULONG_PTR>(pageSize - 1u);
        const auto offset = address - pageBaseValue;
        if ((offset & 0x0Fu) != 0)
        {
            BkDbgLog("RegisterControlFlowGuardCallTarget: unaligned target=%p offset=0x%llX tag=%s", targetAddress,
                     static_cast<unsigned long long>(offset), tag != nullptr ? tag : "<null>");
            if (imageTarget && !requiresXfg)
            {
                return true;
            }
            BkRuntimeReportFault(BkRuntimeFaultCode::ControlFlowCallTargetRegisterFailed,
                                 reinterpret_cast<std::uint64_t>(targetAddress), 3);
            return false;
        }

        auto *pageBase = reinterpret_cast<void *>(pageBaseValue);
        ULONG_PTR flags = CFG_CALL_TARGET_VALID;
        if (wantsXfg)
        {
            flags |= CFG_CALL_TARGET_VALID_XFG;
        }

        {
            BkSr71InternalScope scope;
            if (ApplyCallTargetFlags(fn, pageBase, pageSize, offset, flags))
            {
                BkDbgLog("RegisterControlFlowGuardCallTarget: target=%p page=%p offset=0x%llX flags=0x%llX tag=%s",
                         targetAddress, pageBase, static_cast<unsigned long long>(offset),
                         static_cast<unsigned long long>(flags), tag != nullptr ? tag : "<null>");
                return true;
            }
        }

        const DWORD firstError = GetLastError();
        if (wantsXfg && !requiresXfg)
        {
            BkSr71InternalScope scope;
            if (ApplyCallTargetFlags(fn, pageBase, pageSize, offset, CFG_CALL_TARGET_VALID))
            {
                BkDbgLog("RegisterControlFlowGuardCallTarget: XFG audit fallback target=%p gle=%lu tag=%s",
                         targetAddress, static_cast<unsigned long>(firstError), tag != nullptr ? tag : "<null>");
                return true;
            }
        }

        BkDbgLog("RegisterControlFlowGuardCallTarget: failed target=%p page=%p offset=0x%llX flags=0x%llX gle=%lu tag=%s",
                 targetAddress, pageBase, static_cast<unsigned long long>(offset),
                 static_cast<unsigned long long>(flags), static_cast<unsigned long>(firstError),
                 tag != nullptr ? tag : "<null>");
        BkRuntimeReportFault(BkRuntimeFaultCode::ControlFlowCallTargetRegisterFailed,
                             reinterpret_cast<std::uint64_t>(targetAddress), firstError);
        return false;
    }

    void ResetControlFlowGuardPolicyCache() noexcept
    {
        InterlockedExchange(&g_CfgPolicyState, 0);
        g_CfgPolicyFlags = 0;
        g_CfgPolicyLastError = 0;
        InterlockedExchange(&g_SetCfgTargetsState, 0);
        g_SetCfgTargets = nullptr;
    }
}
