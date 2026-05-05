#include "internal.h"

typedef struct _BK_TARGET_EXIT_WATCH_CONTEXT
{
    HANDLE ProcessHandle;
    DWORD ProcessId;
} BK_TARGET_EXIT_WATCH_CONTEXT, *PBK_TARGET_EXIT_WATCH_CONTEXT;

static VOID ControllerInjectionPublishTargetExit(_In_ DWORD ProcessId, _In_ DWORD ExitCode)
{
    BKIPC_ETW_EVENT event;
    BOOLEAN exceptionExit = (ExitCode & 0xC0000000u) == 0xC0000000u;

    if (ProcessId == 0)
    {
        return;
    }

    ZeroMemory(&event, sizeof(event));
    event.Source = BlackbirdIpcEtwSourceBlackbird;
    event.Family = BlackbirdIpcEtwFamilyProcess;
    event.EventProcessId = ProcessId;
    event.ProcessId = ProcessId;
    event.TargetPid = ProcessId;
    event.Severity = ExitCode == 0 ? 1u : (exceptionExit ? 6u : 3u);
    event.CreateStatus = (INT32)ExitCode;
    (void)StringCchCopyW(event.EventName, RTL_NUMBER_OF(event.EventName), L"TargetExit");
    (void)StringCchCopyA(event.ClassName, RTL_NUMBER_OF(event.ClassName), "target-lifecycle");
    (void)StringCchCopyA(event.Operation, RTL_NUMBER_OF(event.Operation), exceptionExit ? "exception-exit" : "exit");
    if (exceptionExit)
    {
        (void)StringCchCopyA(event.DetectionName, RTL_NUMBER_OF(event.DetectionName), "TARGET_PROCESS_EXCEPTION");
    }
    else if (ExitCode != 0)
    {
        (void)StringCchCopyA(event.DetectionName, RTL_NUMBER_OF(event.DetectionName), "TARGET_PROCESS_NONZERO_EXIT");
    }
    (void)StringCchPrintfW(event.Reason, RTL_NUMBER_OF(event.Reason), L"target-exit pid=%lu exitCode=0x%08lX%s",
                           (unsigned long)ProcessId, (unsigned long)ExitCode,
                           exceptionExit ? L" probableException=true" : L"");
    ControllerDispatchEtwEvent(&event);
}

static DWORD WINAPI ControllerInjectionTargetExitWatchThread(_In_ LPVOID Context)
{
    PBK_TARGET_EXIT_WATCH_CONTEXT ctx = (PBK_TARGET_EXIT_WATCH_CONTEXT)Context;
    DWORD exitCode = STILL_ACTIVE;

    if (ctx == NULL)
    {
        return ERROR_INVALID_PARAMETER;
    }

    if (WaitForSingleObject(ctx->ProcessHandle, INFINITE) == WAIT_OBJECT_0 &&
        GetExitCodeProcess(ctx->ProcessHandle, &exitCode))
    {
        ControllerInjectionPublishTargetExit(ctx->ProcessId, exitCode);
        (void)ControllerDropProcessSubscriptions(ctx->ProcessId, "target-exit");
    }

    if (ctx->ProcessHandle != NULL && ctx->ProcessHandle != INVALID_HANDLE_VALUE)
    {
        CloseHandle(ctx->ProcessHandle);
    }
    HeapFree(GetProcessHeap(), 0, ctx);
    return ERROR_SUCCESS;
}

static BOOL ControllerInjectionStartTargetExitWatcher(_In_ HANDLE ProcessHandle, _In_ DWORD ProcessId)
{
    PBK_TARGET_EXIT_WATCH_CONTEXT ctx;
    HANDLE duplicateHandle = NULL;
    HANDLE threadHandle;

    if (ProcessHandle == NULL || ProcessHandle == INVALID_HANDLE_VALUE || ProcessId == 0)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    if (!DuplicateHandle(GetCurrentProcess(), ProcessHandle, GetCurrentProcess(), &duplicateHandle,
                         SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, 0))
    {
        return FALSE;
    }

    ctx = (PBK_TARGET_EXIT_WATCH_CONTEXT)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*ctx));
    if (ctx == NULL)
    {
        CloseHandle(duplicateHandle);
        SetLastError(ERROR_OUTOFMEMORY);
        return FALSE;
    }

    ctx->ProcessHandle = duplicateHandle;
    ctx->ProcessId = ProcessId;
    threadHandle = CreateThread(NULL, 0, ControllerInjectionTargetExitWatchThread, ctx, 0, NULL);
    if (threadHandle == NULL)
    {
        DWORD err = GetLastError();
        CloseHandle(duplicateHandle);
        HeapFree(GetProcessHeap(), 0, ctx);
        SetLastError(err);
        return FALSE;
    }

    CloseHandle(threadHandle);
    return TRUE;
}

BOOL ControllerInjectionLaunchTargetProcessNative(_In_ HANDLE ClientToken, _In_z_ PCWSTR ImagePath,
                                                  _In_ const std::wstring &CommandLineTemplate,
                                                  _In_opt_z_ PCWSTR CurrentDirectory, _In_opt_ PVOID EnvironmentBlock,
                                                  _In_opt_ HANDLE ParentProcessHandle,
                                                  _In_reads_opt_(InheritedHandleCount) const HANDLE *InheritedHandles,
                                                  _In_ DWORD InheritedHandleCount, _In_ BOOL InheritHandles,
                                                  _Out_ PROCESS_INFORMATION *ProcessInformation)
{
    HMODULE ntdll = NULL;
    NtCreateUserProcessFn ntCreateUserProcess = NULL;
    RtlCreateProcessParametersExFn rtlCreateProcessParametersEx = NULL;
    RtlDestroyProcessParametersFn rtlDestroyProcessParameters = NULL;
    RtlDosPathNameToNtPathName_U_WithStatusFn rtlDosPathToNt = NULL;
    RtlFreeUnicodeStringFn rtlFreeUnicodeString = NULL;
    HANDLE processHandle = NULL;
    HANDLE threadHandle = NULL;
    PVOID processParameters = NULL;
    BB_UNICODE_STRING ntImagePath;
    BB_UNICODE_STRING commandLine;
    BB_UNICODE_STRING currentDirectoryUs;
    BB_UNICODE_STRING desktopInfo;
    BB_PS_CREATE_INFO createInfo;
    BB_PS_ATTRIBUTE_LIST attributes;
    std::vector<WCHAR> mutableCommandLine = ControllerInjectionMakeMutableCommandLine(CommandLineTemplate);
    LONG status;
    DWORD err = ERROR_SUCCESS;
    DWORD attributeCount = 0;

    if (ClientToken == NULL || ImagePath == NULL || ImagePath[0] == L'\0' || ProcessInformation == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    ZeroMemory(ProcessInformation, sizeof(*ProcessInformation));
    ZeroMemory(&ntImagePath, sizeof(ntImagePath));
    ZeroMemory(&commandLine, sizeof(commandLine));
    ZeroMemory(&currentDirectoryUs, sizeof(currentDirectoryUs));
    ZeroMemory(&desktopInfo, sizeof(desktopInfo));
    ZeroMemory(&createInfo, sizeof(createInfo));
    ZeroMemory(&attributes, sizeof(attributes));

    ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll == NULL)
    {
        err = GetLastError() == ERROR_SUCCESS ? ERROR_MOD_NOT_FOUND : GetLastError();
        goto Cleanup;
    }

    ntCreateUserProcess = reinterpret_cast<NtCreateUserProcessFn>(GetProcAddress(ntdll, "NtCreateUserProcess"));
    rtlCreateProcessParametersEx =
        reinterpret_cast<RtlCreateProcessParametersExFn>(GetProcAddress(ntdll, "RtlCreateProcessParametersEx"));
    rtlDestroyProcessParameters =
        reinterpret_cast<RtlDestroyProcessParametersFn>(GetProcAddress(ntdll, "RtlDestroyProcessParameters"));
    rtlDosPathToNt = reinterpret_cast<RtlDosPathNameToNtPathName_U_WithStatusFn>(
        GetProcAddress(ntdll, "RtlDosPathNameToNtPathName_U_WithStatus"));
    rtlFreeUnicodeString = reinterpret_cast<RtlFreeUnicodeStringFn>(GetProcAddress(ntdll, "RtlFreeUnicodeString"));
    if (ntCreateUserProcess == NULL || rtlCreateProcessParametersEx == NULL || rtlDestroyProcessParameters == NULL ||
        rtlDosPathToNt == NULL || rtlFreeUnicodeString == NULL)
    {
        err = ERROR_PROC_NOT_FOUND;
        goto Cleanup;
    }

    status = rtlDosPathToNt(ImagePath, &ntImagePath, NULL, NULL);
    if (status < 0 || ntImagePath.Buffer == NULL)
    {
        err = ControllerInjectionNtStatusToWin32(status);
        goto Cleanup;
    }

    ControllerInjectionInitUnicodeString(&commandLine, mutableCommandLine.data());
    if (CurrentDirectory != NULL && CurrentDirectory[0] != L'\0')
    {
        ControllerInjectionInitUnicodeString(&currentDirectoryUs, CurrentDirectory);
    }
    ControllerInjectionInitUnicodeString(&desktopInfo, L"winsta0\\default");

    status = rtlCreateProcessParametersEx(
        &processParameters, &ntImagePath, NULL, currentDirectoryUs.Buffer != NULL ? &currentDirectoryUs : NULL,
        &commandLine, EnvironmentBlock, NULL, &desktopInfo, NULL, NULL, BB_RTL_USER_PROC_PARAMS_NORMALIZED);
    if (status < 0 || processParameters == NULL)
    {
        err = ControllerInjectionNtStatusToWin32(status);
        goto Cleanup;
    }

    attributes.Attributes[attributeCount].Attribute = BB_PS_ATTRIBUTE_IMAGE_NAME;
    attributes.Attributes[attributeCount].Size = ntImagePath.Length;
    attributes.Attributes[attributeCount].ValuePtr = ntImagePath.Buffer;
    attributes.Attributes[attributeCount].ReturnLength = NULL;
    attributeCount += 1;

    attributes.Attributes[attributeCount].Attribute = BB_PS_ATTRIBUTE_TOKEN;
    attributes.Attributes[attributeCount].Size = sizeof(ClientToken);
    attributes.Attributes[attributeCount].Value = (ULONG_PTR)ClientToken;
    attributes.Attributes[attributeCount].ReturnLength = NULL;
    attributeCount += 1;

    if (ParentProcessHandle != NULL)
    {
        attributes.Attributes[attributeCount].Attribute = BB_PS_ATTRIBUTE_PARENT_PROCESS;
        attributes.Attributes[attributeCount].Size = sizeof(ParentProcessHandle);
        attributes.Attributes[attributeCount].Value = (ULONG_PTR)ParentProcessHandle;
        attributes.Attributes[attributeCount].ReturnLength = NULL;
        attributeCount += 1;
    }

    if (InheritedHandles != NULL && InheritedHandleCount != 0 && attributeCount < RTL_NUMBER_OF(attributes.Attributes))
    {
        attributes.Attributes[attributeCount].Attribute = BB_PS_ATTRIBUTE_HANDLE_LIST;
        attributes.Attributes[attributeCount].Size = sizeof(HANDLE) * InheritedHandleCount;
        attributes.Attributes[attributeCount].ValuePtr = (PVOID)InheritedHandles;
        attributes.Attributes[attributeCount].ReturnLength = NULL;
        attributeCount += 1;
    }

    attributes.TotalLength = sizeof(SIZE_T) + (sizeof(BB_PS_ATTRIBUTE) * attributeCount);
    createInfo.Size = sizeof(createInfo);
    createInfo.State = BbPsCreateInitialState;

    status = ntCreateUserProcess(&processHandle, &threadHandle,
                                 PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION |
                                     PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_TERMINATE | PROCESS_SET_INFORMATION |
                                     PROCESS_SUSPEND_RESUME | SYNCHRONIZE,
                                 THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT |
                                     THREAD_QUERY_INFORMATION | THREAD_TERMINATE | SYNCHRONIZE,
                                 NULL, NULL, InheritHandles ? BB_PROCESS_CREATE_FLAGS_INHERIT_HANDLES : 0,
                                 BB_THREAD_CREATE_FLAGS_CREATE_SUSPENDED, processParameters, &createInfo, &attributes);

    if (status < 0)
    {
        err = ControllerInjectionNtStatusToWin32(status);
        ControllerLog("[INJ] native NtCreateUserProcess failed image=%ws status=0x%08lX win32=%lu createState=%lu\n",
                      ImagePath, (unsigned long)status, err, (unsigned long)createInfo.State);
        goto Cleanup;
    }

    ProcessInformation->hProcess = processHandle;
    ProcessInformation->hThread = threadHandle;
    ProcessInformation->dwProcessId = GetProcessId(processHandle);
    ProcessInformation->dwThreadId = GetThreadId(threadHandle);
    processHandle = NULL;
    threadHandle = NULL;
    err = ERROR_SUCCESS;

Cleanup:
    if (threadHandle != NULL)
    {
        CloseHandle(threadHandle);
    }
    if (processHandle != NULL)
    {
        CloseHandle(processHandle);
    }
    if (processParameters != NULL && rtlDestroyProcessParameters != NULL)
    {
        rtlDestroyProcessParameters(processParameters);
    }
    if (ntImagePath.Buffer != NULL && rtlFreeUnicodeString != NULL)
    {
        rtlFreeUnicodeString(&ntImagePath);
    }
    if (err != ERROR_SUCCESS)
    {
        SetLastError(err);
        return FALSE;
    }

    return TRUE;
}

BOOL ControllerInjectionLaunchTargetProcess(_In_ HANDLE ClientPipe,
                                            _In_ const BKIPC_SET_USER_HOOK_TARGET_REQUEST *Request,
                                            _In_opt_z_ PCWSTR DeferredLaunchGateEventName,
                                            _Out_ PROCESS_INFORMATION *ProcessInformation)
{
    PROCESS_INFORMATION processInfo;
    std::wstring commandLineTemplate;
    HANDLE clientToken = NULL;
    HANDLE parentHandle = NULL;
    PWSTR environmentBlock = NULL;
    BOOL allowBroadHandleInheritance = FALSE;
    BOOL consoleSubsystem = FALSE;
    BOOL guiSubsystem = FALSE;
    DWORD err = ERROR_SUCCESS;
    DWORD priorityClass = 0;
    DWORD clientProcessId = 0;
    DWORD clientSessionId = 0;
    DWORD originalTokenSessionId = 0;
    DWORD tokenSessionId = 0;
    DWORD tokenSourceSessionId = 0;
    DWORD createdSessionId = 0;
    PCWSTR currentDirectory = NULL;
    PCWSTR imagePath = NULL;
    USHORT imageSubsystem = IMAGE_SUBSYSTEM_UNKNOWN;
    BOOL haveClientSession = FALSE;
    BOOL requireDesktopSession = FALSE;

    if (ClientPipe == NULL || ClientPipe == INVALID_HANDLE_VALUE || Request == NULL || Request->ImagePath[0] == L'\0' ||
        ProcessInformation == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    imagePath = Request->ImagePath;
    allowBroadHandleInheritance = (Request->InheritHandles != 0);
    currentDirectory = (Request->WorkingDirectory[0] != L'\0') ? Request->WorkingDirectory : NULL;
    priorityClass = ControllerInjectionMapPriorityClass(Request->PriorityClass);
    haveClientSession = ControllerInjectionQueryPipeClientSession(ClientPipe, &clientProcessId, &clientSessionId);
    if (!haveClientSession || clientProcessId == 0)
    {
        err = GetLastError();
        ControllerLog("[INJ] native launch client session unavailable image=%ws err=%lu\n", imagePath,
                      err == ERROR_SUCCESS ? ERROR_NO_TOKEN : err);
        SetLastError(err == ERROR_SUCCESS ? ERROR_NO_TOKEN : err);
        return FALSE;
    }

    ControllerLog("[INJ] native launch client session pid=%lu session=%lu image=%ws\n", clientProcessId,
                  clientSessionId, imagePath);

    ZeroMemory(&processInfo, sizeof(processInfo));
    if (!ControllerInjectionBuildLaunchCommandLine(imagePath, Request->CommandLineArguments, &commandLineTemplate))
    {
        err = GetLastError();
        ControllerLog("[INJ] native launch command-line build failed image=%ws argsChars=%llu err=%lu\n", imagePath,
                      Request->CommandLineArguments[0] != L'\0'
                          ? (unsigned long long)wcslen(Request->CommandLineArguments)
                          : 0ull,
                      err == ERROR_SUCCESS ? ERROR_INVALID_PARAMETER : err);
        SetLastError(err == ERROR_SUCCESS ? ERROR_INVALID_PARAMETER : err);
        return FALSE;
    }
    ControllerLog("[INJ] native launch command line ready image=%ws argsChars=%llu totalChars=%llu\n", imagePath,
                  Request->CommandLineArguments[0] != L'\0' ? (unsigned long long)wcslen(Request->CommandLineArguments)
                                                            : 0ull,
                  (unsigned long long)commandLineTemplate.size());

    if (ControllerInjectionReadImageSubsystem(imagePath, &imageSubsystem))
    {
        consoleSubsystem = (imageSubsystem == IMAGE_SUBSYSTEM_WINDOWS_CUI);
        guiSubsystem = (imageSubsystem == IMAGE_SUBSYSTEM_WINDOWS_GUI);
    }

    if (!ControllerInjectionEnablePrivilege(SE_INCREASE_QUOTA_NAME))
    {
        ControllerLog("[INJ] native launch privilege enable skipped privilege=%ws err=%lu\n", SE_INCREASE_QUOTA_NAME,
                      GetLastError());
    }
    if (!ControllerInjectionEnablePrivilege(SE_ASSIGNPRIMARYTOKEN_NAME))
    {
        ControllerLog("[INJ] native launch privilege enable skipped privilege=%ws err=%lu\n",
                      SE_ASSIGNPRIMARYTOKEN_NAME, GetLastError());
    }

    if (Request->IntegrityLevel == BK_LAUNCH_INTEGRITY_SYSTEM)
    {
        if (!ControllerInjectionAcquirePrimaryTokenFromProcess(GetCurrentProcessId(), &clientToken))
        {
            err = GetLastError();
            ControllerLog("[INJ] native launch SYSTEM token unavailable image=%ws err=%lu\n", imagePath,
                          err == ERROR_SUCCESS ? ERROR_ACCESS_DENIED : err);
            SetLastError(err == ERROR_SUCCESS ? ERROR_ACCESS_DENIED : err);
            return FALSE;
        }
        tokenSourceSessionId = clientSessionId;
        ControllerLog("[INJ] native launch using explicit SYSTEM token image=%ws requestedSession=%lu\n", imagePath,
                      clientSessionId);
    }
    else if (!ControllerInjectionAcquireActiveInteractiveUserToken(&clientToken, &tokenSourceSessionId))
    {
        err = GetLastError();
        ControllerLog(
            "[INJ] native launch active interactive user token unavailable image=%ws clientPid=%lu clientSession=%lu integrity=%lu err=%lu\n",
            imagePath, clientProcessId, clientSessionId, Request->IntegrityLevel,
            err == ERROR_SUCCESS ? ERROR_NO_TOKEN : err);
        SetLastError(err == ERROR_SUCCESS ? ERROR_NO_TOKEN : err);
        return FALSE;
    }
    else
    {
        ControllerLog(
            "[INJ] native launch using active interactive user token image=%ws activeSession=%lu clientPid=%lu clientSession=%lu integrity=%lu\n",
            imagePath, tokenSourceSessionId, clientProcessId, clientSessionId, Request->IntegrityLevel);
    }

    requireDesktopSession = tokenSourceSessionId != 0;
    if (!ControllerInjectionEnsureTokenSession(clientToken, tokenSourceSessionId, &originalTokenSessionId,
                                               &tokenSessionId))
    {
        err = GetLastError();
        ControllerLog(
            "[INJ] native launch token session mismatch/fix failed image=%ws clientPid=%lu targetSession=%lu err=%lu\n",
            imagePath, clientProcessId, tokenSourceSessionId, err == ERROR_SUCCESS ? ERROR_ACCESS_DENIED : err);
        goto Cleanup;
    }
    ControllerLog(
        "[INJ] native launch token session ready image=%ws targetSession=%lu originalTokenSession=%lu tokenSession=%lu changed=%u\n",
        imagePath, tokenSourceSessionId, originalTokenSessionId, tokenSessionId,
        originalTokenSessionId != tokenSessionId ? 1u : 0u);

    if (!ControllerInjectionApplyRequestedIntegrity(clientToken, Request->IntegrityLevel))
    {
        err = GetLastError();
        ControllerLog("[INJ] native launch integrity apply failed image=%ws integrity=%lu err=%lu\n", imagePath,
                      Request->IntegrityLevel, err == ERROR_SUCCESS ? ERROR_ACCESS_DENIED : err);
        goto Cleanup;
    }

    if (Request->ParentProcessId != 0)
    {
        parentHandle = OpenProcess(PROCESS_CREATE_PROCESS | PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION,
                                   FALSE, Request->ParentProcessId);
        if (parentHandle == NULL)
        {
            err = GetLastError();
            ControllerLog("[INJ] native launch parent open failed image=%ws parentPid=%lu err=%lu\n", imagePath,
                          Request->ParentProcessId, err == ERROR_SUCCESS ? ERROR_INVALID_HANDLE : err);
            goto Cleanup;
        }
    }

    if (!ControllerInjectionBuildEnvironmentBlock(
            clientToken, Request->EnvironmentOverrides, TRUE,
            (Request->Flags & BKIPC_USER_HOOK_FLAG_DEFER_LAUNCH_GATE_RELEASE) != 0, DeferredLaunchGateEventName,
            &environmentBlock))
    {
        err = GetLastError();
        goto Cleanup;
    }

    if (!ControllerInjectionLaunchTargetProcessNative(clientToken, imagePath, commandLineTemplate, currentDirectory,
                                                      environmentBlock, parentHandle, NULL, 0,
                                                      allowBroadHandleInheritance ? TRUE : FALSE, &processInfo))
    {
        err = GetLastError();
        ControllerLog(
            "[INJ] native NtCreateUserProcess launch failed image=%ws clientPid=%lu parentPid=%lu inheritHandles=%u err=%lu\n",
            imagePath, clientProcessId, Request->ParentProcessId, Request->InheritHandles ? 1u : 0u,
            err == ERROR_SUCCESS ? ERROR_ACCESS_DENIED : err);
        SetLastError(err == ERROR_SUCCESS ? ERROR_ACCESS_DENIED : err);
        goto Cleanup;
    }
    ControllerLog("[INJ] native NtCreateUserProcess launch succeeded image=%ws pid=%lu tid=%lu console=%u gui=%u\n",
                  imagePath, processInfo.dwProcessId, processInfo.dwThreadId, consoleSubsystem ? 1u : 0u,
                  guiSubsystem ? 1u : 0u);

    if (!ProcessIdToSessionId(processInfo.dwProcessId, &createdSessionId))
    {
        err = GetLastError();
        ControllerLog("[INJ] launch session verify failed pid=%lu image=%ws err=%lu\n", processInfo.dwProcessId,
                      imagePath, err == ERROR_SUCCESS ? ERROR_GEN_FAILURE : err);
        (void)TerminateProcess(processInfo.hProcess, 1);
        SetLastError(err == ERROR_SUCCESS ? ERROR_GEN_FAILURE : err);
        goto Cleanup;
    }

    ControllerLog(
        "[INJ] launch created pid=%lu session=%lu expectedSession=%lu clientPid=%lu interactive=%u console=%u gui=%u\n",
        processInfo.dwProcessId, createdSessionId, tokenSourceSessionId, clientProcessId, 1u,
        consoleSubsystem ? 1u : 0u, guiSubsystem ? 1u : 0u);
    if (requireDesktopSession && createdSessionId != tokenSourceSessionId)
    {
        ControllerLog(
            "[INJ] launch created in wrong session pid=%lu actualSession=%lu expectedSession=%lu; terminating\n",
            processInfo.dwProcessId, createdSessionId, tokenSourceSessionId);
        (void)TerminateProcess(processInfo.hProcess, 1);
        err = ERROR_ACCESS_DENIED;
        SetLastError(err);
        goto Cleanup;
    }

    if (!ControllerInjectionStartTargetExitWatcher(processInfo.hProcess, processInfo.dwProcessId))
    {
        ControllerLog("[INJ] target exit watcher unavailable pid=%lu err=%lu\n", processInfo.dwProcessId,
                      GetLastError());
    }

    if (priorityClass != 0 && !SetPriorityClass(processInfo.hProcess, priorityClass))
    {
        err = GetLastError();
        (void)TerminateProcess(processInfo.hProcess, 1);
        (void)CloseHandle(processInfo.hThread);
        (void)CloseHandle(processInfo.hProcess);
        processInfo.hThread = NULL;
        processInfo.hProcess = NULL;
        SetLastError(err == ERROR_SUCCESS ? ERROR_GEN_FAILURE : err);
        goto Cleanup;
    }

    if (Request->AffinityMask != 0 && !SetProcessAffinityMask(processInfo.hProcess, (DWORD_PTR)Request->AffinityMask))
    {
        err = GetLastError();
        (void)TerminateProcess(processInfo.hProcess, 1);
        (void)CloseHandle(processInfo.hThread);
        (void)CloseHandle(processInfo.hProcess);
        processInfo.hThread = NULL;
        processInfo.hProcess = NULL;
        SetLastError(err == ERROR_SUCCESS ? ERROR_GEN_FAILURE : err);
        goto Cleanup;
    }

    *ProcessInformation = processInfo;
    processInfo.hProcess = NULL;
    processInfo.hThread = NULL;
    err = ERROR_SUCCESS;

Cleanup:
    if (clientToken != NULL)
    {
        CloseHandle(clientToken);
    }
    if (processInfo.hThread != NULL)
    {
        CloseHandle(processInfo.hThread);
    }
    if (processInfo.hProcess != NULL)
    {
        CloseHandle(processInfo.hProcess);
    }
    if (environmentBlock != NULL)
    {
        HeapFree(GetProcessHeap(), 0, environmentBlock);
    }
    if (parentHandle != NULL)
    {
        CloseHandle(parentHandle);
    }
    if (err != ERROR_SUCCESS)
    {
        SetLastError(err);
        return FALSE;
    }

    return TRUE;
}
