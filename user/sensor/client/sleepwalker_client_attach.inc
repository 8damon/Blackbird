static BOOL LaunchTargetSuspended(_In_ const SLEEPWALKER_TARGET_SPEC *Spec, _Out_ SLEEPWALKER_LAUNCH_TARGET *Launch,
                                  _Out_ DWORD *Pid)
{
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;

    if (Spec == NULL || Launch == NULL || Pid == NULL || Spec->Kind != SleepwalkerTargetLaunch)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    *Pid = 0;
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);

    if (!CreateProcessW(Spec->PathRaw, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi))
    {
        return FALSE;
    }

    Launch->Active = TRUE;
    Launch->Resumed = FALSE;
    Launch->ProcessInfo = pi;
    *Pid = pi.dwProcessId;
    return TRUE;
}

static BOOL ResolveTargetPid(_In_ const SLEEPWALKER_TARGET_SPEC *Spec, _Out_ DWORD *Pid,
                             _Out_opt_ SLEEPWALKER_LAUNCH_TARGET *Launch)
{
    DWORD foundPid;

    if (Spec == NULL || Pid == NULL)
    {
        return FALSE;
    }

    *Pid = 0;
    if (Launch != NULL)
    {
        ZeroMemory(Launch, sizeof(*Launch));
    }

    switch (Spec->Kind)
    {
    case SleepwalkerTargetPid:
        *Pid = Spec->Pid;
        return TRUE;

    case SleepwalkerTargetName:
        foundPid = FindProcessIdByNameW(Spec->Name);
        if (foundPid == 0)
        {
            SetLastError(ERROR_NOT_FOUND);
            return FALSE;
        }
        *Pid = foundPid;
        return TRUE;

    case SleepwalkerTargetPath:
        foundPid = FindProcessIdByPathSpec(Spec);
        if (foundPid != 0)
        {
            *Pid = foundPid;
            return TRUE;
        }

        wprintf(L"[*] Waiting for path match via ProcessTelemetry/ImageTelemetry: %ls\n", Spec->PathRaw);
        if (!WaitForPathLaunchViaEtw(Spec, &foundPid))
        {
            return FALSE;
        }
        *Pid = foundPid;
        return TRUE;

    case SleepwalkerTargetLaunch:
        if (Launch == NULL)
        {
            SetLastError(ERROR_INVALID_PARAMETER);
            return FALSE;
        }
        return LaunchTargetSuspended(Spec, Launch, Pid);
    }

    SetLastError(ERROR_INVALID_PARAMETER);
    return FALSE;
}

static VOID PrimeTargetImageHint(_In_ HANDLE Device, _In_ const SLEEPWALKER_TARGET_SPEC *Spec, _In_ DWORD TargetPid)
{
    WCHAR imagePath[SLEEPWALKER_PATH_CHARS];
    HANDLE process;
    DWORD pathChars;

    if (Spec == NULL || TargetPid == 0)
    {
        return;
    }

    imagePath[0] = L'\0';
    if ((Spec->Kind == SleepwalkerTargetLaunch || Spec->Kind == SleepwalkerTargetPath) && Spec->PathRaw[0] != L'\0')
    {
        (void)StringCchCopyW(imagePath, RTL_NUMBER_OF(imagePath), Spec->PathRaw);
    }
    else
    {
        process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, TargetPid);
        if (process != NULL)
        {
            pathChars = RTL_NUMBER_OF(imagePath);
            if (!QueryFullProcessImageNameW(process, 0, imagePath, &pathChars))
            {
                imagePath[0] = L'\0';
            }
            CloseHandle(process);
        }
    }

    if (imagePath[0] == L'\0' && Device != INVALID_HANDLE_VALUE)
    {
        (void)SLEEPWALKERSCQueryProcessImagePath(Device, TargetPid, imagePath, (DWORD)RTL_NUMBER_OF(imagePath));
    }

    SLEEPWALKERPrimeProcessImagePath((ULONGLONG)TargetPid, imagePath);
}

