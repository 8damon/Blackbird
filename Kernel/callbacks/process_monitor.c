#include <ntddk.h>
#include <ntstrsafe.h>
#include "..\core\control.h"
#include "..\core\pool_compat.h"
#include "..\core\runtime_config.h"
#include "..\core\tempus_debug.h"
#include "..\telemetry\etw.h"
#include "..\core\unicode_utils.h"
#include "process_monitor.h"

static volatile LONG g_ProcessMonitorRegistered = 0;
static volatile LONG g_ProcessMonitorFailureCounter = 0;
static volatile ULONG g_BlackbirdInterfacePid = 0;
static volatile LONG g_BlackbirdInterfaceBootstrapCreatorPid = 0;
static volatile LONG g_BlackbirdInterfaceBootstrapParentPid = 0;
static volatile LONG64 g_BlackbirdInterfaceBootstrapExpires100ns = 0;
static volatile ULONG g_BlackbirdControllerPid = 0;
static volatile LONG g_BlackbirdControllerReady = 0;
static volatile ULONG g_BlackbirdNetSvcPid = 0;
static volatile LONG g_BlackbirdNetSvcReady = 0;
static volatile ULONG g_ServicesPid = 0;

#define BK_LAUNCH_BOOTSTRAP_PID_SLOTS 32
#define BK_INTERFACE_BOOTSTRAP_GRACE_100NS (10ull * 1000ull * 1000ull * 10ull)

static volatile LONG g_LaunchBootstrapPids[BK_LAUNCH_BOOTSTRAP_PID_SLOTS];
static volatile LONG g_LaunchBootstrapWriteIndex = -1;

NTKERNELAPI ULONGLONG PsGetProcessStartKey(_In_ PEPROCESS Process);
NTKERNELAPI ULONG PsGetProcessSessionIdEx(_In_ PEPROCESS Process);
NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(_In_ HANDLE ProcessId, _Outptr_ PEPROCESS *Process);
NTSYSAPI NTSTATUS NTAPI SeLocateProcessImageName(_In_ PEPROCESS Process, _Out_ PUNICODE_STRING *pImageFileName);
NTSYSAPI NTSTATUS NTAPI ObQueryNameString(_In_ PVOID Object,
                                          _Out_writes_bytes_opt_(Length) POBJECT_NAME_INFORMATION ObjectNameInfo,
                                          _In_ ULONG Length, _Out_ PULONG ReturnLength);

static VOID BkcprocArmLaunchBootstrapPid(_In_ UINT32 ProcessId)
{
    UINT32 i;
    LONG replacementIndex;

    if (ProcessId == 0)
    {
        return;
    }

    for (i = 0; i < RTL_NUMBER_OF(g_LaunchBootstrapPids); ++i)
    {
        LONG observedPid = InterlockedCompareExchange(&g_LaunchBootstrapPids[i], 0, 0);

        if ((UINT32)observedPid == ProcessId)
        {
            return;
        }
        if (observedPid == 0 && InterlockedCompareExchange(&g_LaunchBootstrapPids[i], (LONG)ProcessId, 0) == 0)
        {
            return;
        }
    }

    replacementIndex = InterlockedIncrement(&g_LaunchBootstrapWriteIndex);
    if (replacementIndex < 0)
    {
        replacementIndex = 0;
        InterlockedExchange(&g_LaunchBootstrapWriteIndex, 0);
    }
    InterlockedExchange(&g_LaunchBootstrapPids[(UINT32)replacementIndex % RTL_NUMBER_OF(g_LaunchBootstrapPids)],
                        (LONG)ProcessId);
}

static VOID BkcprocClearLaunchBootstrapPid(_In_ UINT32 ProcessId)
{
    UINT32 i;

    if (ProcessId == 0)
    {
        return;
    }

    for (i = 0; i < RTL_NUMBER_OF(g_LaunchBootstrapPids); ++i)
    {
        (void)InterlockedCompareExchange(&g_LaunchBootstrapPids[i], 0, (LONG)ProcessId);
    }
}

static BOOLEAN BkcprocProcessPathMatchesImage(_In_z_ PCWSTR ImageName, _In_opt_ PCUNICODE_STRING Candidate)
{
    UNICODE_STRING expected;
    UNICODE_STRING baseName;
    USHORT i;

    if (Candidate == NULL || Candidate->Buffer == NULL || Candidate->Length == 0 || ImageName == NULL ||
        ImageName[0] == L'\0')
    {
        return FALSE;
    }

    RtlInitUnicodeString(&expected, ImageName);
    if (BkstrUnicodeEquals(Candidate, &expected, TRUE))
    {
        return TRUE;
    }

    baseName = *Candidate;
    for (i = (USHORT)(Candidate->Length / sizeof(WCHAR)); i > 0; --i)
    {
        if (Candidate->Buffer[i - 1] == L'\\' || Candidate->Buffer[i - 1] == L'/')
        {
            baseName.Buffer = Candidate->Buffer + i;
            baseName.Length = Candidate->Length - (USHORT)(i * sizeof(WCHAR));
            baseName.MaximumLength = baseName.Length;
            break;
        }
    }

    return BkstrUnicodeEquals(&baseName, &expected, TRUE);
}

static BOOLEAN BkcprocProcessPathIsSystem32Image(_In_opt_ PCUNICODE_STRING Candidate)
{
    static const WCHAR kWindowsSystem32[] = L"\\Windows\\System32\\";
    static const WCHAR kSystemRootSystem32[] = L"\\SystemRoot\\System32\\";

    if (Candidate == NULL || Candidate->Buffer == NULL || Candidate->Length == 0)
    {
        return FALSE;
    }

    return BkstrUnicodeContainsInsensitive(Candidate, kWindowsSystem32,
                                           (USHORT)(RTL_NUMBER_OF(kWindowsSystem32) - 1)) ||
           BkstrUnicodeContainsInsensitive(Candidate, kSystemRootSystem32,
                                           (USHORT)(RTL_NUMBER_OF(kSystemRootSystem32) - 1));
}

static VOID BkcprocClearInterfaceBootstrap(VOID)
{
    InterlockedExchange(&g_BlackbirdInterfaceBootstrapCreatorPid, 0);
    InterlockedExchange(&g_BlackbirdInterfaceBootstrapParentPid, 0);
    InterlockedExchange64(&g_BlackbirdInterfaceBootstrapExpires100ns, 0);
}

static VOID BkcprocTrackInterfacePid(_In_ UINT32 ProcessId, _In_opt_ HANDLE ParentProcessId,
                                     _In_opt_ HANDLE CreatorProcessId)
{
    UINT32 parentPid;
    UINT32 creatorPid;
    ULONGLONG expires;

    if (ProcessId == 0)
    {
        return;
    }

    parentPid = (UINT32)(ULONG_PTR)ParentProcessId;
    creatorPid = (UINT32)(ULONG_PTR)CreatorProcessId;
    expires = KeQueryInterruptTime() + BK_INTERFACE_BOOTSTRAP_GRACE_100NS;

    InterlockedExchange((volatile LONG *)&g_BlackbirdInterfacePid, (LONG)ProcessId);
    InterlockedExchange(&g_BlackbirdInterfaceBootstrapCreatorPid, (LONG)creatorPid);
    InterlockedExchange(&g_BlackbirdInterfaceBootstrapParentPid, (LONG)parentPid);
    InterlockedExchange64(&g_BlackbirdInterfaceBootstrapExpires100ns, (LONG64)expires);
}

static BOOLEAN BkcprocRegisterNamedPid(_In_ UINT32 ProcessId, _In_z_ PCWSTR ImageName, _Inout_ volatile ULONG *PidSlot,
                                       _Inout_opt_ volatile LONG *ReadySlot)
{
    NTSTATUS status;
    PEPROCESS process = NULL;
    PUNICODE_STRING imagePath = NULL;
    BOOLEAN matches = FALSE;

    if (ProcessId == 0 || ImageName == NULL || ImageName[0] == L'\0' || PidSlot == NULL)
    {
        return FALSE;
    }

    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &process);
    if (!NT_SUCCESS(status))
    {
        return FALSE;
    }

    status = SeLocateProcessImageName(process, &imagePath);
    if (NT_SUCCESS(status) && imagePath != NULL && imagePath->Buffer != NULL && imagePath->Length != 0)
    {
        matches = BkcprocProcessPathMatchesImage(ImageName, imagePath);
    }

    if (imagePath != NULL)
    {
        ExFreePool(imagePath);
    }
    ObDereferenceObject(process);

    if (!matches)
    {
        return FALSE;
    }

    if (ReadySlot != NULL)
    {
        InterlockedExchange(ReadySlot, 0);
    }
    InterlockedExchange((volatile LONG *)PidSlot, (LONG)ProcessId);
    return TRUE;
}

static BOOLEAN BkcprocProcessIdMatchesAnyImage(_In_ UINT32 ProcessId, _In_reads_(ImageCount) PCWSTR const *ImageNames,
                                               _In_ size_t ImageCount)
{
    NTSTATUS status;
    PEPROCESS process = NULL;
    PUNICODE_STRING imagePath = NULL;
    BOOLEAN matches = FALSE;
    size_t i;

    if (ProcessId == 0 || ImageNames == NULL || ImageCount == 0)
    {
        return FALSE;
    }

    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &process);
    if (!NT_SUCCESS(status))
    {
        return FALSE;
    }

    status = SeLocateProcessImageName(process, &imagePath);
    if (NT_SUCCESS(status) && imagePath != NULL && imagePath->Buffer != NULL && imagePath->Length != 0)
    {
        for (i = 0; i < ImageCount; ++i)
        {
            if (ImageNames[i] != NULL && BkcprocProcessPathMatchesImage(ImageNames[i], imagePath))
            {
                matches = BkcprocProcessPathIsSystem32Image(imagePath);
                break;
            }
        }
    }

    if (imagePath != NULL)
    {
        ExFreePool(imagePath);
    }
    ObDereferenceObject(process);
    return matches;
}

static VOID BkcprocTrackProtectedPid(_In_ UINT32 ProcessId, _In_reads_z_(ImageChars) PCWSTR ImagePath,
                                     _In_ USHORT ImageChars, _In_opt_ PFILE_OBJECT FileObject,
                                     _In_opt_ HANDLE ParentProcessId, _In_opt_ HANDLE CreatorProcessId)
{
    UNICODE_STRING image;

    UNREFERENCED_PARAMETER(FileObject);

    if (ProcessId == 0 || ImagePath == NULL || ImageChars == 0)
    {
        return;
    }

    image.Buffer = (PWSTR)ImagePath;
    image.Length = (USHORT)(ImageChars * sizeof(WCHAR));
    image.MaximumLength = image.Length;

    if (BkcprocProcessPathMatchesImage(L"BlackbirdInterface.exe", &image))
    {
        BkcprocTrackInterfacePid(ProcessId, ParentProcessId, CreatorProcessId);
    }
    if (BkcprocProcessPathMatchesImage(L"BlackbirdController.exe", &image))
    {
        InterlockedExchange((volatile LONG *)&g_BlackbirdControllerPid, (LONG)ProcessId);
        InterlockedExchange(&g_BlackbirdControllerReady, 0);
    }
    if (BkcprocProcessPathMatchesImage(L"BlackbirdNetSvc.exe", &image))
    {
        LONG trackedPid = InterlockedCompareExchange((volatile LONG *)&g_BlackbirdNetSvcPid, 0, 0);
        LONG ready = InterlockedCompareExchange(&g_BlackbirdNetSvcReady, 0, 0);

        /* The NetSvc preview path launches the same executable as a short-lived
         * active-session helper. Once
         * the real NetSvc is marked ready, do not let
         * same-image helpers steal the protected PID slot. */
        if (ready == 0 || trackedPid == 0 || (UINT32)trackedPid == ProcessId)
        {
            InterlockedExchange((volatile LONG *)&g_BlackbirdNetSvcPid, (LONG)ProcessId);
            InterlockedExchange(&g_BlackbirdNetSvcReady, 0);
        }
    }
    if (BkcprocProcessPathMatchesImage(L"services.exe", &image) && BkcprocProcessPathIsSystem32Image(&image))
    {
        InterlockedExchange((volatile LONG *)&g_ServicesPid, (LONG)ProcessId);
    }
}

static VOID BkcprocClearProtectedPid(_In_ UINT32 ProcessId)
{
    if (ProcessId == 0)
    {
        return;
    }

    if ((UINT32)InterlockedCompareExchange((volatile LONG *)&g_BlackbirdInterfacePid, 0, 0) == ProcessId)
    {
        InterlockedCompareExchange((volatile LONG *)&g_BlackbirdInterfacePid, 0, (LONG)ProcessId);
        BkcprocClearInterfaceBootstrap();
    }
    if ((UINT32)InterlockedCompareExchange((volatile LONG *)&g_BlackbirdControllerPid, 0, 0) == ProcessId)
    {
        InterlockedCompareExchange((volatile LONG *)&g_BlackbirdControllerPid, 0, (LONG)ProcessId);
        InterlockedExchange(&g_BlackbirdControllerReady, 0);
    }
    if ((UINT32)InterlockedCompareExchange((volatile LONG *)&g_BlackbirdNetSvcPid, 0, 0) == ProcessId)
    {
        /* Do not call into WFP/Fwpm teardown from the process notify callback.
           This callback runs on the terminating process path; blocking filter cleanup here can
           make TerminateProcess succeed while the process never finishes exiting, which also
           prevents driver unload. Controller explicit disarm and driver unload own WFP teardown. */
        InterlockedCompareExchange((volatile LONG *)&g_BlackbirdNetSvcPid, 0, (LONG)ProcessId);
        InterlockedExchange(&g_BlackbirdNetSvcReady, 0);
    }
    if ((UINT32)InterlockedCompareExchange((volatile LONG *)&g_ServicesPid, 0, 0) == ProcessId)
    {
        InterlockedCompareExchange((volatile LONG *)&g_ServicesPid, 0, (LONG)ProcessId);
    }
}

static VOID BkcprocFillImagePathFromFileObject(_In_opt_ PFILE_OBJECT FileObject,
                                               _Out_writes_z_(OutputChars) PWSTR Output, _In_ size_t OutputChars)
{
    NTSTATUS status;
    ULONG bytes = 0;
    POBJECT_NAME_INFORMATION nameInfo = NULL;

    if (FileObject == NULL || Output == NULL || OutputChars == 0 || Output[0] != L'\0')
    {
        return;
    }

    status = ObQueryNameString(FileObject, NULL, 0, &bytes);
    if ((status != STATUS_INFO_LENGTH_MISMATCH && status != STATUS_BUFFER_TOO_SMALL) || bytes < sizeof(*nameInfo))
    {
        return;
    }

    nameInfo = (POBJECT_NAME_INFORMATION)BkpoolAllocateCompat(POOL_FLAG_PAGED, bytes, 'pNbB');
    if (nameInfo == NULL)
    {
        return;
    }

    status = ObQueryNameString(FileObject, nameInfo, bytes, &bytes);
    if (NT_SUCCESS(status) && nameInfo->Name.Buffer != NULL && nameInfo->Name.Length != 0)
    {
        (void)RtlStringCchCopyNW(Output, OutputChars, nameInfo->Name.Buffer, nameInfo->Name.Length / sizeof(WCHAR));
    }

    ExFreePoolWithTag(nameInfo, 'pNbB');
}

static VOID BkcprocFillImagePathFromProcessObject(_In_ PEPROCESS Process, _Out_writes_z_(OutputChars) PWSTR Output,
                                                  _In_ size_t OutputChars)
{
    NTSTATUS status;
    PUNICODE_STRING imageName = NULL;

    if (Process == NULL || Output == NULL || OutputChars == 0 || Output[0] != L'\0')
    {
        return;
    }

    status = SeLocateProcessImageName(Process, &imageName);
    if (!NT_SUCCESS(status) || imageName == NULL || imageName->Buffer == NULL || imageName->Length == 0)
    {
        if (imageName != NULL)
        {
            ExFreePool(imageName);
        }
        return;
    }

    (void)RtlStringCchCopyNW(Output, OutputChars, imageName->Buffer, imageName->Length / sizeof(WCHAR));
    ExFreePool(imageName);
}

static VOID BkcprocDetectImageTampering(_In_ HANDLE ProcessId, _Inout_ PPS_CREATE_NOTIFY_INFO CreateInfo,
                                        _In_opt_z_ PCWSTR ImagePath)
{
    WCHAR reason[512];
    ULONG indicators = 0;
    ULONG severity;

    if (CreateInfo == NULL || CreateInfo->FileObject == NULL || ProcessId == NULL)
    {
        return;
    }

    if (CreateInfo->FileObject->DeletePending)
    {
        indicators |= 0x1u;
    }
    if (CreateInfo->FileObject->WriteAccess || CreateInfo->FileObject->SharedWrite)
    {
        indicators |= 0x2u;
    }
    if (CreateInfo->FileObject->DeleteAccess || CreateInfo->FileObject->SharedDelete)
    {
        indicators |= 0x4u;
    }

    if (indicators == 0)
    {
        return;
    }

    if ((indicators & 0x1u) == 0u && (indicators & 0x2u) == 0u)
    {
        return;
    }

    severity = ((indicators & 0x1u) != 0u) ? 7u : 6u;
    reason[0] = L'\0';
    (void)RtlStringCchPrintfW(
        reason, RTL_NUMBER_OF(reason),
        L"process image FILE_OBJECT abnormality deletePending=%u writeAccess=%u sharedWrite=%u deleteAccess=%u sharedDelete=%u path=%ws — associated with image tampering techniques such as Ghosting, Herpaderping, and Doppelganging",
        (unsigned int)(CreateInfo->FileObject->DeletePending ? 1u : 0u),
        (unsigned int)(CreateInfo->FileObject->WriteAccess ? 1u : 0u),
        (unsigned int)(CreateInfo->FileObject->SharedWrite ? 1u : 0u),
        (unsigned int)(CreateInfo->FileObject->DeleteAccess ? 1u : 0u),
        (unsigned int)(CreateInfo->FileObject->SharedDelete ? 1u : 0u),
        (ImagePath != NULL && ImagePath[0] != L'\0') ? ImagePath : L"(unknown)");

    if ((indicators & 0x1u) != 0u)
    {
        BketwLogDetectionEvent("PROCESS_IMAGE_GHOSTING_SUSPECT", severity, ProcessId, ProcessId, 0, indicators, 0,
                               reason);
    }
    else
    {
        BketwLogDetectionEvent("PROCESS_IMAGE_TAMPER_SUSPECT", severity, ProcessId, ProcessId, 0, indicators, 0,
                               reason);
    }
}
static BOOLEAN BkcprocProcessCmdlineContains(_In_z_ PCWSTR CmdLine, _In_z_ PCWSTR Needle, _In_ USHORT NeedleLen)
{
    UNICODE_STRING cmdUs;
    RtlInitUnicodeString(&cmdUs, CmdLine);
    return BkstrUnicodeContainsInsensitive(&cmdUs, Needle, NeedleLen);
}

static VOID BkcprocProcessDetectPowerShell(_In_ HANDLE ProcessId, _In_z_ PCWSTR ImagePath, _In_z_ PCWSTR CommandLine)
{
    UNICODE_STRING imageUs;

    if (ImagePath == NULL || ImagePath[0] == L'\0' || CommandLine == NULL || CommandLine[0] == L'\0')
        return;

    RtlInitUnicodeString(&imageUs, ImagePath);
    if (!BkcprocProcessPathMatchesImage(L"powershell.exe", &imageUs) &&
        !BkcprocProcessPathMatchesImage(L"pwsh.exe", &imageUs))
    {
        return;
    }

    if (BkcprocProcessCmdlineContains(CommandLine, L"amsiInitFailed", 14) ||
        BkcprocProcessCmdlineContains(CommandLine, L"AmsiScanBuffer", 14) ||
        BkcprocProcessCmdlineContains(CommandLine, L"[Ref].Assembly", 14) ||
        BkcprocProcessCmdlineContains(CommandLine, L"amsiContext", 11))
    {
        BketwLogDetectionEvent("POWERSHELL_AMSI_BYPASS", 8, ProcessId, ProcessId, 0, 0, 0, CommandLine);
        return;
    }

    if (BkcprocProcessCmdlineContains(CommandLine, L"DownloadString", 14) ||
        BkcprocProcessCmdlineContains(CommandLine, L"DownloadFile", 12) ||
        BkcprocProcessCmdlineContains(CommandLine, L"Net.WebClient", 13) ||
        BkcprocProcessCmdlineContains(CommandLine, L"Invoke-WebRequest", 17) ||
        BkcprocProcessCmdlineContains(CommandLine, L"Invoke-Expression", 17) ||
        BkcprocProcessCmdlineContains(CommandLine, L"IEX (", 5) ||
        BkcprocProcessCmdlineContains(CommandLine, L"IEX(", 4))
    {
        BketwLogDetectionEvent("POWERSHELL_DOWNLOAD_CRADLE", 7, ProcessId, ProcessId, 0, 0, 0, CommandLine);
        return;
    }

    if (BkcprocProcessCmdlineContains(CommandLine, L"-EncodedCommand", 15) ||
        BkcprocProcessCmdlineContains(CommandLine, L" -enc ", 6) ||
        BkcprocProcessCmdlineContains(CommandLine, L" -ec ", 5))
    {
        BketwLogDetectionEvent("POWERSHELL_OBFUSCATED_CMDLINE", 6, ProcessId, ProcessId, 0, 0, 0, CommandLine);
        return;
    }

    if (BkcprocProcessCmdlineContains(CommandLine, L"-ExecutionPolicy Bypass", 23) ||
        BkcprocProcessCmdlineContains(CommandLine, L"-Exec Bypass", 12) ||
        BkcprocProcessCmdlineContains(CommandLine, L"-NoProfile", 10) ||
        BkcprocProcessCmdlineContains(CommandLine, L"-NoP ", 5) ||
        BkcprocProcessCmdlineContains(CommandLine, L"-NonInteractive", 15) ||
        BkcprocProcessCmdlineContains(CommandLine, L"-WindowStyle Hidden", 19) ||
        BkcprocProcessCmdlineContains(CommandLine, L"-W Hidden", 9))
    {
        BketwLogDetectionEvent("POWERSHELL_SUSPICIOUS_INVOCATION", 5, ProcessId, ProcessId, 0, 0, 0, CommandLine);
    }
}

static VOID BkcprocProcessDetectLolbin(_In_ HANDLE ProcessId, _In_z_ PCWSTR ImagePath, _In_z_ PCWSTR CommandLine)
{
    static const PCWSTR kLolbins[] = {L"certutil.exe", L"mshta.exe",     L"wscript.exe",         L"cscript.exe",
                                      L"regsvr32.exe", L"rundll32.exe",  L"msiexec.exe",         L"bitsadmin.exe",
                                      L"regasm.exe",   L"regsvcs.exe",   L"installutil.exe",     L"cmstp.exe",
                                      L"odbcconf.exe", L"msbuild.exe",   L"dnscmd.exe",          L"wmic.exe",
                                      L"forfiles.exe", L"pcalua.exe",    L"esentutl.exe",        L"expand.exe",
                                      L"ieexec.exe",   L"mavinject.exe", L"msdeploy.exe",        L"msdt.exe",
                                      L"bash.exe",     L"replace.exe",   L"presentationhost.exe"};
    UNICODE_STRING imageUs;
    ULONG i;

    if (ImagePath == NULL || ImagePath[0] == L'\0')
        return;

    RtlInitUnicodeString(&imageUs, ImagePath);

    for (i = 0; i < RTL_NUMBER_OF(kLolbins); ++i)
    {
        if (!BkcprocProcessPathMatchesImage(kLolbins[i], &imageUs))
            continue;

        if (CommandLine != NULL && CommandLine[0] != L'\0' &&
            (BkcprocProcessCmdlineContains(CommandLine, L"http", 4) ||
             BkcprocProcessCmdlineContains(CommandLine, L"ftp://", 6) ||
             BkcprocProcessCmdlineContains(CommandLine, L"download", 8) ||
             BkcprocProcessCmdlineContains(CommandLine, L"urlcache", 8) ||
             BkcprocProcessCmdlineContains(CommandLine, L"scrobj", 6) ||
             BkcprocProcessCmdlineContains(CommandLine, L"regsvr", 6)))
        {
            BketwLogDetectionEvent("LOLBIN_NETWORK_ACTIVITY", 6, ProcessId, ProcessId, 0, 0, 0, ImagePath);
        }
        else
        {
            BketwLogDetectionEvent("LOLBIN_EXECUTION", 4, ProcessId, ProcessId, 0, 0, 0, ImagePath);
        }
        return;
    }
}

static VOID BkcprocProcessDetectScriptHostAbuse(_In_ HANDLE ProcessId, _In_z_ PCWSTR ImagePath,
                                                _In_z_ PCWSTR CommandLine)
{
    UNICODE_STRING imageUs;

    if (ImagePath == NULL || ImagePath[0] == L'\0' || CommandLine == NULL || CommandLine[0] == L'\0')
        return;

    RtlInitUnicodeString(&imageUs, ImagePath);
    if (!BkcprocProcessPathMatchesImage(L"wscript.exe", &imageUs) &&
        !BkcprocProcessPathMatchesImage(L"cscript.exe", &imageUs))
    {
        return;
    }

    if ((BkcprocProcessCmdlineContains(CommandLine, L".js", 3) ||
         BkcprocProcessCmdlineContains(CommandLine, L".vbs", 4) ||
         BkcprocProcessCmdlineContains(CommandLine, L".wsf", 4)) &&
        (BkcprocProcessCmdlineContains(CommandLine, L"\\Temp\\", 6) ||
         BkcprocProcessCmdlineContains(CommandLine, L"\\AppData\\", 9) ||
         BkcprocProcessCmdlineContains(CommandLine, L"\\Downloads\\", 11) ||
         BkcprocProcessCmdlineContains(CommandLine, L"\\Desktop\\", 9) ||
         BkcprocProcessCmdlineContains(CommandLine, L"\\Public\\", 8)))
    {
        BketwLogDetectionEvent("SCRIPT_HOST_ABUSE", 5, ProcessId, ProcessId, 0, 0, 0, CommandLine);
    }
}

static VOID BkcprocProcessNotifyRoutineEx(_Inout_ PEPROCESS Process, _In_ HANDLE ProcessId,
                                          _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    ULONGLONG tempusStartQpc = BktmpEnter(BktmpSubsystemProcessMonitor);
    WCHAR imagePath[BK_MAX_IMAGE_PATH_CHARS];
    WCHAR commandLine[512];
    HANDLE parentPid = NULL;
    HANDLE creatorPid = NULL;
    HANDLE creatorTid = NULL;
    ULONGLONG startKey = 0;
    ULONG sessionId = 0;
    NTSTATUS createStatus = STATUS_SUCCESS;
    BOOLEAN isCreate = FALSE;
    BOOLEAN launchBound = FALSE;

    imagePath[0] = L'\0';
    commandLine[0] = L'\0';

    if (Process != NULL)
    {
        startKey = PsGetProcessStartKey(Process);
        sessionId = PsGetProcessSessionIdEx(Process);
    }

    if (CreateInfo != NULL)
    {
        isCreate = TRUE;
        parentPid = CreateInfo->ParentProcessId;
        creatorPid = CreateInfo->CreatingThreadId.UniqueProcess;
        creatorTid = CreateInfo->CreatingThreadId.UniqueThread;
        createStatus = CreateInfo->CreationStatus;

        if (NT_SUCCESS(createStatus) && ProcessId != NULL && CreateInfo->FileObject != NULL)
        {
            BkcprocFillImagePathFromFileObject(CreateInfo->FileObject, imagePath, RTL_NUMBER_OF(imagePath));
            if (imagePath[0] != L'\0')
            {
                UNICODE_STRING fileObjectImagePath;

                RtlInitUnicodeString(&fileObjectImagePath, imagePath);
                launchBound = BkctlBindPendingLaunchProcess((UINT32)(ULONG_PTR)ProcessId, &fileObjectImagePath);
                BkcprocTrackProtectedPid((UINT32)(ULONG_PTR)ProcessId, imagePath, (USHORT)wcslen(imagePath),
                                         CreateInfo->FileObject, parentPid, creatorPid);
            }
        }

        if (!launchBound && NT_SUCCESS(createStatus) && ProcessId != NULL && CreateInfo->ImageFileName != NULL)
        {
            launchBound = BkctlBindPendingLaunchProcess((UINT32)(ULONG_PTR)ProcessId, CreateInfo->ImageFileName);
        }

        if (imagePath[0] == L'\0')
        {
            BkstrSafeCopyUnicode(CreateInfo->ImageFileName, imagePath, RTL_NUMBER_OF(imagePath));
        }

        BkstrSafeCopyUnicode(CreateInfo->CommandLine, commandLine, RTL_NUMBER_OF(commandLine));

        BkcprocFillImagePathFromProcessObject(Process, imagePath, RTL_NUMBER_OF(imagePath));
        if (!launchBound && NT_SUCCESS(createStatus) && ProcessId != NULL && imagePath[0] != L'\0')
        {
            UNICODE_STRING resolvedImagePath;

            RtlInitUnicodeString(&resolvedImagePath, imagePath);
            (void)BkctlBindPendingLaunchProcess((UINT32)(ULONG_PTR)ProcessId, &resolvedImagePath);
        }
        if (ProcessId != NULL && imagePath[0] != L'\0')
        {
            BkcprocTrackProtectedPid((UINT32)(ULONG_PTR)ProcessId, imagePath, (USHORT)wcslen(imagePath),
                                     CreateInfo->FileObject, parentPid, creatorPid);
        }
        if (launchBound && NT_SUCCESS(createStatus) && ProcessId != NULL)
        {
            BkcprocArmLaunchBootstrapPid((UINT32)(ULONG_PTR)ProcessId);
        }
    }
    else if (ProcessId != NULL)
    {
        BkcprocClearLaunchBootstrapPid((UINT32)(ULONG_PTR)ProcessId);
        BkcprocClearProtectedPid((UINT32)(ULONG_PTR)ProcessId);
    }

    if (isCreate && NT_SUCCESS(createStatus))
    {
        BkcprocDetectImageTampering(ProcessId, CreateInfo, imagePath);
        BkcprocProcessDetectLolbin(ProcessId, imagePath, commandLine);
        BkcprocProcessDetectPowerShell(ProcessId, imagePath, commandLine);
        BkcprocProcessDetectScriptHostAbuse(ProcessId, imagePath, commandLine);
    }

    BketwLogProcessEvent(ProcessId, parentPid, creatorPid, creatorTid, startKey, sessionId, isCreate, createStatus,
                         (imagePath[0] != L'\0') ? imagePath : NULL, (commandLine[0] != L'\0') ? commandLine : NULL);

    /* PPID spoofing: when a caller uses PROC_THREAD_ATTRIBUTE_PARENT_PROCESS to override
     * the inherited parent, the kernel-reported ParentProcessId diverges from the
     * CreatingThreadId.UniqueProcess field.  Normal CreateProcess always has them equal.
     * Only flag in user sessions (sessionId > 0) to suppress noise from SCM/WMI patterns
     * and skip the System process (PID 4). */
    if (isCreate && NT_SUCCESS(createStatus) && ProcessId != NULL && sessionId > 0 && parentPid != NULL &&
        creatorPid != NULL && parentPid != creatorPid && (ULONG_PTR)parentPid > 4 && (ULONG_PTR)creatorPid > 4)
    {
        BketwLogDetectionEvent("PARENT_PID_SPOOF_SUSPECT", 5, ProcessId, ProcessId, 0, 0, 0,
                               L"process has explicit parent-process override — ParentPid differs from CreatorPid");
    }
    BktmpLeave(BktmpSubsystemProcessMonitor, tempusStartQpc);
}

NTSTATUS
BkcprocInitialize(VOID)
{
    NTSTATUS status;
    LONG failures;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (InterlockedCompareExchange(&g_ProcessMonitorRegistered, 0, 0) != 0)
    {
        return STATUS_SUCCESS;
    }

    InterlockedExchange((volatile LONG *)&g_BlackbirdInterfacePid, 0);
    BkcprocClearInterfaceBootstrap();
    InterlockedExchange((volatile LONG *)&g_BlackbirdControllerPid, 0);
    InterlockedExchange(&g_BlackbirdControllerReady, 0);
    InterlockedExchange((volatile LONG *)&g_BlackbirdNetSvcPid, 0);
    InterlockedExchange(&g_BlackbirdNetSvcReady, 0);
    RtlZeroMemory((PVOID)g_LaunchBootstrapPids, sizeof(g_LaunchBootstrapPids));
    InterlockedExchange(&g_LaunchBootstrapWriteIndex, -1);

    status = PsSetCreateProcessNotifyRoutineEx(BkcprocProcessNotifyRoutineEx, FALSE);
    if (!NT_SUCCESS(status))
    {
        failures = InterlockedIncrement(&g_ProcessMonitorFailureCounter);
        if (failures == 1 || ((failures & 0xFF) == 0))
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                       "BK: process monitor callback registration failed status=0x%08X total=%lu.\n", status,
                       (ULONG)failures);
        }
        return status;
    }

    InterlockedExchange(&g_ProcessMonitorRegistered, 1);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "BK: process monitor initialized.\n");
    return STATUS_SUCCESS;
}

VOID BkcprocUninitialize(VOID)
{
    NTSTATUS status;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        return;
    }
    if (InterlockedCompareExchange(&g_ProcessMonitorRegistered, 0, 0) == 0)
    {
        return;
    }

    status = PsSetCreateProcessNotifyRoutineEx(BkcprocProcessNotifyRoutineEx, TRUE);
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "BK: process monitor callback removal failed; monitor remains registered (status=0x%08X).\n",
                   status);
        return;
    }

    InterlockedExchange(&g_ProcessMonitorRegistered, 0);
    InterlockedExchange((volatile LONG *)&g_BlackbirdInterfacePid, 0);
    BkcprocClearInterfaceBootstrap();
    InterlockedExchange((volatile LONG *)&g_BlackbirdControllerPid, 0);
    InterlockedExchange(&g_BlackbirdControllerReady, 0);
    InterlockedExchange((volatile LONG *)&g_BlackbirdNetSvcPid, 0);
    InterlockedExchange(&g_BlackbirdNetSvcReady, 0);
    InterlockedExchange((volatile LONG *)&g_ServicesPid, 0);
    RtlZeroMemory((PVOID)g_LaunchBootstrapPids, sizeof(g_LaunchBootstrapPids));
    InterlockedExchange(&g_LaunchBootstrapWriteIndex, -1);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "BK: process monitor uninitialized.\n");
}

BOOLEAN
BkcprocSelfCheck(VOID)
{
    return (InterlockedCompareExchange(&g_ProcessMonitorRegistered, 0, 0) != 0);
}

BOOLEAN BkcprocIsInterfacePid(_In_ UINT32 ProcessId)
{
    if (ProcessId == 0)
    {
        return FALSE;
    }

    return (UINT32)InterlockedCompareExchange((volatile LONG *)&g_BlackbirdInterfacePid, 0, 0) == ProcessId;
}

BOOLEAN BkcprocIsControllerPid(_In_ UINT32 ProcessId)
{
    if (ProcessId == 0)
    {
        return FALSE;
    }

    return (UINT32)InterlockedCompareExchange((volatile LONG *)&g_BlackbirdControllerPid, 0, 0) == ProcessId;
}

BOOLEAN BkcprocIsNetSvcPid(_In_ UINT32 ProcessId)
{
    if (ProcessId == 0)
    {
        return FALSE;
    }

    return (UINT32)InterlockedCompareExchange((volatile LONG *)&g_BlackbirdNetSvcPid, 0, 0) == ProcessId;
}

BOOLEAN BkcprocIsControllerReadyPid(_In_ UINT32 ProcessId)
{
    return BkcprocIsControllerPid(ProcessId) && InterlockedCompareExchange(&g_BlackbirdControllerReady, 0, 0) != 0;
}

BOOLEAN BkcprocIsNetSvcReadyPid(_In_ UINT32 ProcessId)
{
    return BkcprocIsNetSvcPid(ProcessId) && InterlockedCompareExchange(&g_BlackbirdNetSvcReady, 0, 0) != 0;
}

BOOLEAN BkcprocRegisterInterfacePid(_In_ UINT32 ProcessId)
{
    BOOLEAN registered = BkcprocRegisterNamedPid(ProcessId, L"BlackbirdInterface.exe", &g_BlackbirdInterfacePid, NULL);
    if (registered)
    {
        BkcprocClearInterfaceBootstrap();
    }
    return registered;
}

BOOLEAN BkcprocRegisterControllerPid(_In_ UINT32 ProcessId)
{
    return BkcprocRegisterNamedPid(ProcessId, L"BlackbirdController.exe", &g_BlackbirdControllerPid,
                                   &g_BlackbirdControllerReady);
}

BOOLEAN BkcprocRegisterNetSvcPid(_In_ UINT32 ProcessId)
{
    return BkcprocRegisterNamedPid(ProcessId, L"BlackbirdNetSvc.exe", &g_BlackbirdNetSvcPid, &g_BlackbirdNetSvcReady);
}

BOOLEAN BkcprocIsProtectedPid(_In_ UINT32 ProcessId)
{
    if (ProcessId == 0)
    {
        return FALSE;
    }

    if (BkcprocIsInterfacePid(ProcessId) && BkrtIsInterfaceProtectedAccessEnabled())
    {
        return TRUE;
    }

    if (BkrtIsControllerProtectedAccessEnabled())
    {
        if (BkcprocIsControllerReadyPid(ProcessId))
        {
            return TRUE;
        }
        if (BkcprocIsNetSvcReadyPid(ProcessId))
        {
            return TRUE;
        }
    }

    return FALSE;
}

BOOLEAN BkcprocMarkControllerReady(_In_ UINT32 ProcessId)
{
    UINT32 trackedControllerPid;

    if (ProcessId == 0)
    {
        return FALSE;
    }

    trackedControllerPid = (UINT32)InterlockedCompareExchange((volatile LONG *)&g_BlackbirdControllerPid, 0, 0);
    if (trackedControllerPid != ProcessId)
    {
        if (!BkcprocRegisterControllerPid(ProcessId))
        {
            return FALSE;
        }
    }

    InterlockedExchange(&g_BlackbirdControllerReady, 1);
    return TRUE;
}

BOOLEAN BkcprocMarkNetSvcReady(_In_ UINT32 ProcessId)
{
    UINT32 trackedPid;

    if (ProcessId == 0)
    {
        return FALSE;
    }

    trackedPid = (UINT32)InterlockedCompareExchange((volatile LONG *)&g_BlackbirdNetSvcPid, 0, 0);
    if (trackedPid != ProcessId)
    {
        if (!BkcprocRegisterNetSvcPid(ProcessId))
        {
            return FALSE;
        }
    }

    InterlockedExchange(&g_BlackbirdNetSvcReady, 1);
    return TRUE;
}

BOOLEAN BkcprocIsTrustedProtectedCaller(_In_ UINT32 CallerPid, _In_ UINT32 TargetPid)
{
    UINT32 interfacePid;
    UINT32 controllerPid;
    UINT32 netSvcPid;
    UINT32 servicesPid;
    UINT32 interfaceCreatorPid;
    UINT32 interfaceParentPid;
    LONG64 interfaceBootstrapExpires;

    if (CallerPid == 0 || TargetPid == 0)
    {
        return FALSE;
    }
    if (CallerPid == TargetPid)
    {
        return TRUE;
    }

    interfacePid = (UINT32)InterlockedCompareExchange((volatile LONG *)&g_BlackbirdInterfacePid, 0, 0);
    controllerPid = (UINT32)InterlockedCompareExchange((volatile LONG *)&g_BlackbirdControllerPid, 0, 0);
    netSvcPid = (UINT32)InterlockedCompareExchange((volatile LONG *)&g_BlackbirdNetSvcPid, 0, 0);
    servicesPid = (UINT32)InterlockedCompareExchange((volatile LONG *)&g_ServicesPid, 0, 0);
    interfaceCreatorPid =
        (UINT32)InterlockedCompareExchange(&g_BlackbirdInterfaceBootstrapCreatorPid, 0, 0);
    interfaceParentPid = (UINT32)InterlockedCompareExchange(&g_BlackbirdInterfaceBootstrapParentPid, 0, 0);
    interfaceBootstrapExpires = InterlockedCompareExchange64(&g_BlackbirdInterfaceBootstrapExpires100ns, 0, 0);

    if (CallerPid == 4)
    {
        return TRUE;
    }
    if (CallerPid == servicesPid)
    {
        return TRUE;
    }
    if (BkcprocIsKnownSystemBrokerPid(CallerPid))
    {
        /*
         * CreateProcess/CreateProcessAsUser can transiently open the caller as
         * parent through OS
         * broker processes. Stripping those handles breaks
         * protected Blackbird processes spawning service
         * children and active
         * session helpers.
         */
        return TRUE;
    }

    if (TargetPid == interfacePid && interfaceBootstrapExpires != 0 &&
        (CallerPid == interfaceCreatorPid || CallerPid == interfaceParentPid) &&
        (LONG64)KeQueryInterruptTime() <= interfaceBootstrapExpires)
    {
        /*
         * Interface handle protection can be armed from a prior UI session.  On the
         * next launch, the process-create caller must still receive usable initial
         * process/thread handles so user-mode CreateProcess can finish bootstrap and
         * resume the primary thread.  Controller/NetSvc avoid this by becoming
         * protected only after readiness; the interface is image-tracked, so give
         * only its actual creator/parent a short startup allowance.
         */
        return TRUE;
    }

    if (CallerPid == interfacePid && TargetPid == controllerPid)
    {
        return TRUE;
    }
    if (CallerPid == controllerPid && TargetPid == interfacePid)
    {
        return TRUE;
    }
    if (CallerPid == controllerPid && TargetPid == netSvcPid)
    {
        return TRUE;
    }

    return FALSE;
}

BOOLEAN BkcprocIsKnownSystemBrokerPid(_In_ UINT32 ProcessId)
{
    static PCWSTR const kKnownBrokerImages[] = {L"csrss.exe",    L"smss.exe",  L"wininit.exe",  L"winlogon.exe",
                                                L"services.exe", L"lsass.exe", L"werfault.exe", L"wermgr.exe"};

    return BkcprocProcessIdMatchesAnyImage(ProcessId, kKnownBrokerImages, RTL_NUMBER_OF(kKnownBrokerImages));
}

BOOLEAN BkcprocShouldSuppressLaunchBootstrapNtApi(_In_ UINT32 AttachedPid, _In_ UINT32 ThreadOwnerPid)
{
    UINT32 i;

    if (AttachedPid == 0)
    {
        return FALSE;
    }

    for (i = 0; i < RTL_NUMBER_OF(g_LaunchBootstrapPids); ++i)
    {
        LONG observedPid = InterlockedCompareExchange(&g_LaunchBootstrapPids[i], 0, 0);

        if ((UINT32)observedPid != AttachedPid)
        {
            continue;
        }

        /* During pending-launch bootstrap, kernel code can temporarily run attached to the
         * new process while still executing on the creator's thread. Those syscalls are not
         * target-owned user activity and should stay out of the target's NT API stream. */
        if (ThreadOwnerPid == 0 || ThreadOwnerPid != AttachedPid)
        {
            return TRUE;
        }

        BkcprocClearLaunchBootstrapPid(AttachedPid);
        return FALSE;
    }

    return FALSE;
}
