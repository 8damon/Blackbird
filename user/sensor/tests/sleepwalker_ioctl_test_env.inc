static BOOL EnvFlagEnabled(_In_z_ const char *Name, _In_ BOOL DefaultValue)
{
    char value[16];
    size_t i;

    if (Name == NULL)
    {
        return DefaultValue;
    }

    if (GetEnvironmentVariableA(Name, value, (DWORD)RTL_NUMBER_OF(value)) == 0)
    {
        return DefaultValue;
    }

    for (i = 0; i < RTL_NUMBER_OF(value) && value[i] != '\0'; ++i)
    {
        if (value[i] >= 'A' && value[i] <= 'Z')
        {
            value[i] = (char)(value[i] - 'A' + 'a');
        }
    }

    if (strcmp(value, "1") == 0 || strcmp(value, "true") == 0 || strcmp(value, "yes") == 0 || strcmp(value, "on") == 0)
    {
        return TRUE;
    }
    if (strcmp(value, "0") == 0 || strcmp(value, "false") == 0 || strcmp(value, "no") == 0 || strcmp(value, "off") == 0)
    {
        return FALSE;
    }

    return DefaultValue;
}

static BOOL ExpectRawIoctlFailure(_In_ HANDLE Device, _In_ DWORD Ioctl,
                                  _In_reads_bytes_opt_(InSize) const VOID *InBuffer, _In_ DWORD InSize,
                                  _Out_writes_bytes_opt_(OutSize) VOID *OutBuffer, _In_ DWORD OutSize,
                                  _In_reads_(ExpectedErrorCount) const DWORD *ExpectedErrors,
                                  _In_ size_t ExpectedErrorCount)
{
    DWORD bytes = 0;
    BOOL ok;
    DWORD err;

    ok = DeviceIoControl(Device, Ioctl, (LPVOID)InBuffer, InSize, OutBuffer, OutSize, &bytes, NULL);
    if (ok)
    {
        return FALSE;
    }

    err = GetLastError();
    return ErrorInList(err, ExpectedErrors, ExpectedErrorCount);
}

static BOOL ExpectRawIoctlSuccess(_In_ HANDLE Device, _In_ DWORD Ioctl,
                                  _In_reads_bytes_opt_(InSize) const VOID *InBuffer, _In_ DWORD InSize,
                                  _Out_writes_bytes_opt_(OutSize) VOID *OutBuffer, _In_ DWORD OutSize)
{
    DWORD bytes = 0;

    return DeviceIoControl(Device, Ioctl, (LPVOID)InBuffer, InSize, OutBuffer, OutSize, &bytes, NULL);
}

static VOID RunIoctlContractTests(_In_ HANDLE Device, _In_ DWORD SelfPid, _Inout_ SUITE_RESULTS *Results)
{
    static const DWORD expectedInvalidFunction[] = {ERROR_INVALID_FUNCTION, ERROR_NOT_SUPPORTED};
    static const DWORD expectedNoMore[] = {ERROR_NO_MORE_ITEMS};
    static const DWORD expectedBuffer[] = {ERROR_INSUFFICIENT_BUFFER, ERROR_MORE_DATA};
    static const DWORD expectedInvalidParameter[] = {ERROR_INVALID_PARAMETER};
    static const DWORD expectedNotFound[] = {ERROR_NOT_FOUND};
    SLEEPWALKER_EVENT_RECORD eventRecord;
    SLEEPWALKER_SUBSCRIBE_REQUEST subReq;
    SLEEPWALKER_UNSUBSCRIBE_REQUEST unsubReq;
    SLEEPWALKER_SET_PIDS_REQUEST setReq;
    BYTE tinyOut = 0;

    ZeroMemory(&eventRecord, sizeof(eventRecord));
    ZeroMemory(&subReq, sizeof(subReq));
    ZeroMemory(&unsubReq, sizeof(unsubReq));
    ZeroMemory(&setReq, sizeof(setReq));

    subReq.ProcessId = SelfPid;
    subReq.StreamMask = SLEEPWALKER_STREAM_HANDLE;
    unsubReq.ProcessId = SelfPid;

    RecordResult(
        Results,
        ExpectRawIoctlFailure(Device, (DWORD)CTL_CODE(FILE_DEVICE_SLEEPWALKER, 0x8FF, METHOD_BUFFERED, FILE_ANY_ACCESS),
                              NULL, 0, NULL, 0, expectedInvalidFunction, RTL_NUMBER_OF(expectedInvalidFunction)),
        "unknown IOCTL rejected", "unknown IOCTL was not rejected");

    RecordResult(Results,
                 ExpectRawIoctlFailure(Device, (DWORD)IOCTL_SLEEPWALKER_GET_EVENT, NULL, 0, &eventRecord,
                                       sizeof(eventRecord), expectedNoMore, RTL_NUMBER_OF(expectedNoMore)),
                 "empty event queue returns NO_MORE_ITEMS", "empty event queue did not return NO_MORE_ITEMS");

    RecordResult(Results,
                 ExpectRawIoctlFailure(Device, (DWORD)IOCTL_SLEEPWALKER_GET_EVENT, NULL, 0, &tinyOut, sizeof(tinyOut),
                                       expectedBuffer, RTL_NUMBER_OF(expectedBuffer)),
                 "GET_EVENT short output buffer rejected", "GET_EVENT short output buffer was not rejected");

    RecordResult(Results,
                 ExpectRawIoctlFailure(Device, (DWORD)IOCTL_SLEEPWALKER_GET_STATS, NULL, 0, &tinyOut, sizeof(tinyOut),
                                       expectedBuffer, RTL_NUMBER_OF(expectedBuffer)),
                 "GET_STATS short output buffer rejected", "GET_STATS short output buffer was not rejected");

    RecordResult(Results,
                 ExpectRawIoctlFailure(Device, (DWORD)IOCTL_SLEEPWALKER_SUBSCRIBE, &subReq, sizeof(subReq) - 1, NULL, 0,
                                       expectedBuffer, RTL_NUMBER_OF(expectedBuffer)),
                 "SUBSCRIBE short input buffer rejected", "SUBSCRIBE short input buffer was not rejected");

    RecordResult(Results,
                 ExpectRawIoctlFailure(Device, (DWORD)IOCTL_SLEEPWALKER_UNSUBSCRIBE, &unsubReq, sizeof(unsubReq) - 1,
                                       NULL, 0, expectedBuffer, RTL_NUMBER_OF(expectedBuffer)),
                 "UNSUBSCRIBE short input buffer rejected", "UNSUBSCRIBE short input buffer was not rejected");

    setReq.StreamMask = SLEEPWALKER_STREAM_HANDLE;
    setReq.ProcessCount = 1;
    setReq.ProcessIds[0] = SelfPid;
    RecordResult(Results,
                 ExpectRawIoctlFailure(Device, (DWORD)IOCTL_SLEEPWALKER_SET_PIDS, &setReq, sizeof(setReq) - 1, NULL, 0,
                                       expectedBuffer, RTL_NUMBER_OF(expectedBuffer)),
                 "SET_PIDS short input buffer rejected", "SET_PIDS short input buffer was not rejected");

    setReq.StreamMask = SLEEPWALKER_STREAM_HANDLE;
    setReq.ProcessCount = 0;
    RecordResult(Results,
                 ExpectRawIoctlFailure(Device, (DWORD)IOCTL_SLEEPWALKER_SET_PIDS, &setReq, sizeof(setReq), NULL, 0,
                                       expectedInvalidParameter, RTL_NUMBER_OF(expectedInvalidParameter)),
                 "SET_PIDS zero process count rejected", "SET_PIDS zero process count was not rejected");

    setReq.StreamMask = 0;
    setReq.ProcessCount = 1;
    setReq.ProcessIds[0] = SelfPid;
    RecordResult(Results,
                 ExpectRawIoctlFailure(Device, (DWORD)IOCTL_SLEEPWALKER_SET_PIDS, &setReq, sizeof(setReq), NULL, 0,
                                       expectedInvalidParameter, RTL_NUMBER_OF(expectedInvalidParameter)),
                 "SET_PIDS invalid stream mask rejected", "SET_PIDS invalid stream mask was not rejected");

    setReq.StreamMask = SLEEPWALKER_STREAM_HANDLE;
    setReq.ProcessCount = 2;
    setReq.ProcessIds[0] = 0;
    setReq.ProcessIds[1] = 0;
    RecordResult(Results,
                 ExpectRawIoctlFailure(Device, (DWORD)IOCTL_SLEEPWALKER_SET_PIDS, &setReq, sizeof(setReq), NULL, 0,
                                       expectedInvalidParameter, RTL_NUMBER_OF(expectedInvalidParameter)),
                 "SET_PIDS all-zero PID list rejected", "SET_PIDS all-zero PID list was not rejected");

    unsubReq.ProcessId = 0x7FFFFFFF;
    RecordResult(Results,
                 ExpectRawIoctlFailure(Device, (DWORD)IOCTL_SLEEPWALKER_UNSUBSCRIBE, &unsubReq, sizeof(unsubReq), NULL,
                                       0, expectedNotFound, RTL_NUMBER_OF(expectedNotFound)),
                 "UNSUBSCRIBE unknown PID rejected", "UNSUBSCRIBE unknown PID was not rejected");

    subReq.ProcessId = SelfPid;
    subReq.StreamMask = SLEEPWALKER_STREAM_HANDLE;
    RecordResult(Results,
                 ExpectRawIoctlSuccess(Device, (DWORD)IOCTL_SLEEPWALKER_SUBSCRIBE, &subReq, sizeof(subReq), NULL, 0),
                 "SUBSCRIBE accepts valid request", "SUBSCRIBE rejected valid request");

    unsubReq.ProcessId = SelfPid;
    RecordResult(
        Results,
        ExpectRawIoctlSuccess(Device, (DWORD)IOCTL_SLEEPWALKER_UNSUBSCRIBE, &unsubReq, sizeof(unsubReq), NULL, 0),
        "UNSUBSCRIBE accepts valid request", "UNSUBSCRIBE rejected valid request");
}

