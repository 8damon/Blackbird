static BOOL StartIdleChild(CHILD_CTX *child)
{
    WCHAR imagePath[MAX_PATH];
    WCHAR cmdLine[MAX_PATH + 64];
    STARTUPINFOW si;
    DWORD len;

    ZeroMemory(child, sizeof(*child));
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);

    len = GetModuleFileNameW(NULL, imagePath, (DWORD)RTL_NUMBER_OF(imagePath));
    if (len == 0 || len >= RTL_NUMBER_OF(imagePath))
    {
        return FALSE;
    }

    if (swprintf_s(cmdLine, RTL_NUMBER_OF(cmdLine), L"\"%ls\" %ls", imagePath, SLEEPWALKER_CHILD_ARGW) < 0)
    {
        return FALSE;
    }

    if (!CreateProcessW(imagePath, cmdLine, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &child->Pi))
    {
        return FALSE;
    }

    child->Started = TRUE;
    return TRUE;
}

static BOOL StartSpawnAndTouchChild(CHILD_CTX *child)
{
    WCHAR imagePath[MAX_PATH];
    WCHAR cmdLine[MAX_PATH + 80];
    STARTUPINFOW si;
    DWORD len;

    ZeroMemory(child, sizeof(*child));
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);

    len = GetModuleFileNameW(NULL, imagePath, (DWORD)RTL_NUMBER_OF(imagePath));
    if (len == 0 || len >= RTL_NUMBER_OF(imagePath))
    {
        return FALSE;
    }

    if (swprintf_s(cmdLine, RTL_NUMBER_OF(cmdLine), L"\"%ls\" %ls", imagePath, SLEEPWALKER_CHILD_SPAWN_AND_TOUCH_ARGW) <
        0)
    {
        return FALSE;
    }

    if (!CreateProcessW(imagePath, cmdLine, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &child->Pi))
    {
        return FALSE;
    }

    child->Started = TRUE;
    return TRUE;
}

static void StopIdleChild(CHILD_CTX *child)
{
    DWORD waitResult;

    if (!child->Started)
    {
        return;
    }

    waitResult = WaitForSingleObject(child->Pi.hProcess, 500);
    if (waitResult == WAIT_TIMEOUT)
    {
        (void)TerminateProcess(child->Pi.hProcess, 0);
        (void)WaitForSingleObject(child->Pi.hProcess, 2000);
    }

    CloseHandle(child->Pi.hThread);
    CloseHandle(child->Pi.hProcess);
    ZeroMemory(child, sizeof(*child));
}

static BOOL GenerateMemoryHandleIntent(DWORD pid)
{
    HANDLE p = OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (p == NULL)
    {
        return FALSE;
    }
    CloseHandle(p);
    return TRUE;
}

static BOOL GenerateThreadContextHandleIntent(DWORD tid)
{
    HANDLE t = OpenThread(
        THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_LIMITED_INFORMATION, FALSE, tid);
    if (t == NULL)
    {
        return FALSE;
    }
    CloseHandle(t);
    return TRUE;
}

static BOOL GenerateDuplicateHandleIntent(DWORD pid)
{
    HANDLE src = NULL;
    HANDLE dup = NULL;
    BOOL ok;

    src = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION,
                      FALSE, pid);
    if (src == NULL)
    {
        return FALSE;
    }

    ok = DuplicateHandle(GetCurrentProcess(), src, GetCurrentProcess(), &dup, PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE,
                         0);

    if (dup != NULL)
    {
        CloseHandle(dup);
    }
    CloseHandle(src);
    return ok;
}

static BOOL FindRemoteModuleBase(DWORD pid, PCWSTR moduleName, ULONGLONG *baseOut)
{
    HANDLE snap;
    MODULEENTRY32W me;

    *baseOut = 0;
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE)
    {
        return FALSE;
    }

    ZeroMemory(&me, sizeof(me));
    me.dwSize = sizeof(me);

    if (!Module32FirstW(snap, &me))
    {
        CloseHandle(snap);
        return FALSE;
    }

    do
    {
        if (_wcsicmp(me.szModule, moduleName) == 0)
        {
            *baseOut = (ULONGLONG)(ULONG_PTR)me.modBaseAddr;
            CloseHandle(snap);
            return TRUE;
        }
    } while (Module32NextW(snap, &me));

    CloseHandle(snap);
    return FALSE;
}

static BOOL GenerateRemoteThreadLoadLibraryIntent(DWORD pid)
{
    HANDLE process = NULL;
    HANDLE thread = NULL;
    HMODULE localKernel32;
    FARPROC localLoadLibraryW;
    ULONGLONG remoteKernel32 = 0;
    ULONGLONG remoteStartAddress;
    SIZE_T dllBytes;
    LPVOID remoteBuffer = NULL;
    WCHAR dllName[] = L"kernel32.dll";
    BOOL ok = FALSE;
    SIZE_T written = 0;
    DWORD waitResult;
    DWORD attempt = 0;

    localKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (localKernel32 == NULL)
    {
        return FALSE;
    }

    localLoadLibraryW = GetProcAddress(localKernel32, "LoadLibraryW");
    if (localLoadLibraryW == NULL)
    {
        return FALSE;
    }

    for (attempt = 0; attempt < 40; ++attempt)
    {
        if (FindRemoteModuleBase(pid, L"KERNEL32.DLL", &remoteKernel32))
        {
            break;
        }
        Sleep(50);
    }

    if (remoteKernel32 == 0)
    {
        return FALSE;
    }

    remoteStartAddress =
        remoteKernel32 + ((ULONGLONG)(ULONG_PTR)localLoadLibraryW - (ULONGLONG)(ULONG_PTR)localKernel32);

    process = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
                              PROCESS_VM_READ,
                          FALSE, pid);
    if (process == NULL)
    {
        return FALSE;
    }

    dllBytes = (wcslen(dllName) + 1) * sizeof(WCHAR);
    remoteBuffer = VirtualAllocEx(process, NULL, dllBytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (remoteBuffer == NULL)
    {
        goto Exit;
    }

    if (!WriteProcessMemory(process, remoteBuffer, dllName, dllBytes, &written) || written != dllBytes)
    {
        goto Exit;
    }

    for (attempt = 0; attempt < 3; ++attempt)
    {
        thread = CreateRemoteThread(process, NULL, 0, (LPTHREAD_START_ROUTINE)(ULONG_PTR)remoteStartAddress,
                                    remoteBuffer, 0, NULL);
        if (thread != NULL)
        {
            break;
        }
        Sleep(40);
    }
    if (thread == NULL)
    {
        goto Exit;
    }

    waitResult = WaitForSingleObject(thread, 5000);
    if (waitResult != WAIT_OBJECT_0 && waitResult != WAIT_TIMEOUT)
    {
        goto Exit;
    }

    ok = TRUE;

Exit:
    if (thread != NULL)
    {
        CloseHandle(thread);
    }
    if (remoteBuffer != NULL)
    {
        (void)VirtualFreeEx(process, remoteBuffer, 0, MEM_RELEASE);
    }
    if (process != NULL)
    {
        CloseHandle(process);
    }
    return ok;
}

static BOOL GenerateVmApiCallSurface(DWORD pid)
{
    HANDLE process = NULL;
    LPVOID remote = NULL;
    BYTE payload[64];
    SIZE_T written = 0;
    DWORD oldProtect = 0;
    BOOL ok = FALSE;

    ZeroMemory(payload, sizeof(payload));
    for (DWORD i = 0; i < (DWORD)sizeof(payload); ++i)
    {
        payload[i] = (BYTE)(i ^ 0x5A);
    }

    process = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION,
                          FALSE, pid);
    if (process == NULL)
    {
        return FALSE;
    }

    remote = VirtualAllocEx(process, NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (remote == NULL)
    {
        goto Exit;
    }

    if (!WriteProcessMemory(process, remote, payload, sizeof(payload), &written) || written != sizeof(payload))
    {
        goto Exit;
    }

    if (!VirtualProtectEx(process, remote, 0x1000, PAGE_EXECUTE_READ, &oldProtect))
    {
        goto Exit;
    }

    ok = TRUE;

Exit:
    if (remote != NULL)
    {
        (void)VirtualFreeEx(process, remote, 0, MEM_RELEASE);
    }
    if (process != NULL)
    {
        CloseHandle(process);
    }
    return ok;
}

static BOOL GenerateSuspendedHollowingLikeChain(VOID)
{
    WCHAR imagePath[MAX_PATH];
    WCHAR cmdLine[MAX_PATH + 64];
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    HANDLE process = NULL;
    LPVOID remote = NULL;
    BYTE payload[4096];
    SIZE_T written = 0;
    DWORD oldProtect = 0;
    BOOL chainOk = FALSE;
    BOOL resumed = FALSE;

    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    ZeroMemory(payload, sizeof(payload));
    si.cb = sizeof(si);

    if (GetModuleFileNameW(NULL, imagePath, RTL_NUMBER_OF(imagePath)) == 0)
    {
        return FALSE;
    }
    if (swprintf_s(cmdLine, RTL_NUMBER_OF(cmdLine), L"\"%ls\" %ls", imagePath, SLEEPWALKER_CHILD_ARGW) < 0)
    {
        return FALSE;
    }

    if (!CreateProcessW(imagePath, cmdLine, NULL, NULL, FALSE, CREATE_NO_WINDOW | CREATE_SUSPENDED, NULL, NULL, &si,
                        &pi))
    {
        return FALSE;
    }

    process = pi.hProcess;
    remote = VirtualAllocEx(process, NULL, 0x20000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (remote != NULL)
    {
        for (DWORD i = 0; i < (DWORD)sizeof(payload); ++i)
        {
            payload[i] = (BYTE)(0xA5u ^ i);
        }

        if (WriteProcessMemory(process, remote, payload, sizeof(payload), &written) && written == sizeof(payload))
        {
            if (VirtualProtectEx(process, remote, 0x20000, PAGE_EXECUTE_READ, &oldProtect))
            {
                CONTEXT ctx;
                ZeroMemory(&ctx, sizeof(ctx));
                ctx.ContextFlags = CONTEXT_CONTROL;
                if (GetThreadContext(pi.hThread, &ctx))
                {
                    (void)SetThreadContext(pi.hThread, &ctx);
                }
                chainOk = TRUE;
            }
        }
    }

    if (ResumeThread(pi.hThread) != (DWORD)-1)
    {
        resumed = TRUE;
    }

    if (resumed)
    {
        (void)WaitForSingleObject(process, 400);
    }
    (void)TerminateProcess(process, 0);
    (void)WaitForSingleObject(process, 1500);

    if (remote != NULL)
    {
        (void)VirtualFreeEx(process, remote, 0, MEM_RELEASE);
    }
    CloseHandle(pi.hThread);
    CloseHandle(process);
    return chainOk;
}

static BOOL GenerateRegistryHighValueActivity(void)
{
    HKEY key = NULL;
    DWORD disposition = 0;
    LONG status;
    WCHAR valueName[] = L"SleepwalkerTestSuite";
    WCHAR valueData[] = L"cmd.exe /c exit";

    status = RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, NULL,
                             REG_OPTION_NON_VOLATILE, KEY_SET_VALUE | KEY_QUERY_VALUE, NULL, &key, &disposition);
    if (status != ERROR_SUCCESS)
    {
        return FALSE;
    }
    UNREFERENCED_PARAMETER(disposition);

    status = RegSetValueExW(key, valueName, 0, REG_SZ, (const BYTE *)valueData,
                            (DWORD)((wcslen(valueData) + 1) * sizeof(WCHAR)));

    (void)RegDeleteValueW(key, valueName);
    RegCloseKey(key);

    return (status == ERROR_SUCCESS);
}
