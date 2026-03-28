#include "../include/detection_examples.h"

int DetectionExamplesInternalBenignMain(const wchar_t *mode);
int DetectionExamplesInternalDetectionMain(const wchar_t *mode);

static const DetectionExampleDef g_Examples[] = {
    {"direct-syscall-ntqueryvm", "detection",
     "Direct syscalls for NtQueryVirtualMemory and NtOpenProcess against a remote child.",
     "Direct-syscall handle / process recon style detection.", false, ExampleRunDirectSyscallNtQueryVm},
    {"remote-thread-rwx", "detection",
     "Allocates RWX memory in a remote child, writes a stub, and starts a remote thread.",
     "Injection, non-image executable region, remote thread, shellcode-stage style detections.", false,
     ExampleRunRemoteThread},
    {"ppid-spoof", "detection", "Creates a child with an overridden parent process attribute.",
     "PARENT_PID_SPOOF_SUSPECT / process telemetry anomaly.", false, ExampleRunPpidSpoof},
    {"nt-system-recon", "detection", "Queries system process/module information via NtQuerySystemInformation.",
     "USERMODE_PROCESS_RECON / recon-oriented telemetry.", false, ExampleRunNtSystemRecon},
    {"anti-virt-vm-check", "detection",
     "Runs classic VM artifact checks against adapter MAC prefixes and BIOS manufacturer strings.",
     "Anti-virtualization masking validation / environment artifact checks.", false, ExampleRunVmCheck},
    {"benign-launch", "benign", "Launches a child and terminates it without suspicious cross-process behavior.",
     "No high-confidence detection expected.", true, ExampleRunBenignLaunch},
    {"benign-file-io", "benign", "Creates, writes, reads, and deletes a temporary file.",
     "No high-confidence detection expected.", true, ExampleRunBenignFileIo},
    {"benign-memory", "benign", "Allocates and protects memory in the current process only.",
     "No cross-process memory detection expected.", true, ExampleRunBenignMemory},
    {"benign-process-enum", "benign", "Enumerates processes through Toolhelp snapshot APIs.",
     "No high-confidence detection expected.", true, ExampleRunBenignProcessEnum},
};

static void PrintUsage()
{
    ExamplePrint("DetectionExamples usage:\n");
    ExamplePrint("  DetectionExamples.exe --list\n");
    ExamplePrint("  DetectionExamples.exe --run <name>\n");
    ExamplePrint("  DetectionExamples.exe --run-all-detection\n");
    ExamplePrint("  DetectionExamples.exe --run-all-benign\n");
}

static void PrintScenarioList()
{
    ExamplePrint("\nAvailable scenarios:\n");
    for (size_t i = 0; i < ARRAYSIZE(g_Examples); ++i)
    {
        const auto &example = g_Examples[i];
        ExamplePrint("  %2zu. %-22s [%s] %s\n", i + 1, example.Name, example.Category, example.Expected);
    }
}

static void WaitForEnter()
{
    ExamplePrint("\nPress Enter to continue...");
    fflush(stdout);
    (void)getchar();
}

static const DetectionExampleDef *FindExample(const wchar_t *name)
{
    char narrow[128];
    if (name == nullptr)
    {
        return nullptr;
    }
    if (WideCharToMultiByte(CP_UTF8, 0, name, -1, narrow, ARRAYSIZE(narrow), nullptr, nullptr) == 0)
    {
        return nullptr;
    }
    for (const auto &example : g_Examples)
    {
        if (_stricmp(example.Name, narrow) == 0)
        {
            return &example;
        }
    }
    return nullptr;
}

static int RunMatching(bool benign)
{
    int failures = 0;
    for (const auto &example : g_Examples)
    {
        if (example.Benign != benign)
        {
            continue;
        }
        ExamplePrint("\n[%s] %s\n", example.Benign ? "BENIGN" : "DETECTION", example.Name);
        ExamplePrint("  summary : %s\n", example.Summary);
        ExamplePrint("  expected: %s\n", example.Expected);
        if (example.Run(0, nullptr) != 0)
        {
            failures += 1;
        }
    }
    return failures == 0 ? 0 : 1;
}

static int RunInteractiveMenu()
{
    char input[32];

    for (;;)
    {
        int selection = 0;
        PrintUsage();
        PrintScenarioList();
        ExamplePrint("\n  A. Run all detection scenarios\n");
        ExamplePrint("  B. Run all benign scenarios\n");
        ExamplePrint("  Q. Quit\n");
        ExamplePrint("\nSelect an option: ");
        fflush(stdout);

        ZeroMemory(input, sizeof(input));
        if (fgets(input, sizeof(input), stdin) == nullptr)
        {
            return 0;
        }

        if ((input[0] == 'q') || (input[0] == 'Q'))
        {
            return 0;
        }
        if ((input[0] == 'a') || (input[0] == 'A'))
        {
            (void)RunMatching(false);
            WaitForEnter();
            continue;
        }
        if ((input[0] == 'b') || (input[0] == 'B'))
        {
            (void)RunMatching(true);
            WaitForEnter();
            continue;
        }

        selection = atoi(input);
        if (selection < 1 || selection > (int)ARRAYSIZE(g_Examples))
        {
            ExamplePrint("\nInvalid selection.\n");
            WaitForEnter();
            continue;
        }

        {
            const auto &example = g_Examples[selection - 1];
            ExamplePrint("\n[%s] %s\n", example.Benign ? "BENIGN" : "DETECTION", example.Name);
            ExamplePrint("  summary : %s\n", example.Summary);
            ExamplePrint("  expected: %s\n", example.Expected);
            (void)example.Run(0, nullptr);
        }
        WaitForEnter();
    }
}

int wmain(int argc, wchar_t **argv)
{
    if (argc >= 3 && _wcsicmp(argv[1], L"--internal") == 0)
    {
        int rc = DetectionExamplesInternalBenignMain(argv[2]);
        if (rc >= 0)
        {
            return rc;
        }
        rc = DetectionExamplesInternalDetectionMain(argv[2]);
        return rc >= 0 ? rc : 1;
    }

    if (argc < 2)
    {
        return RunInteractiveMenu();
    }

    if (_wcsicmp(argv[1], L"--list") == 0)
    {
        PrintUsage();
        PrintScenarioList();
        return 0;
    }

    if (_wcsicmp(argv[1], L"--run") == 0)
    {
        const DetectionExampleDef *example;
        if (argc < 3)
        {
            PrintUsage();
            return 1;
        }
        example = FindExample(argv[2]);
        if (example == nullptr)
        {
            ExamplePrint("Unknown scenario: %ls\n", argv[2]);
            return 1;
        }
        ExamplePrint("[%s] %s\n", example->Benign ? "BENIGN" : "DETECTION", example->Name);
        ExamplePrint("  summary : %s\n", example->Summary);
        ExamplePrint("  expected: %s\n", example->Expected);
        return example->Run(argc - 2, argv + 2);
    }

    if (_wcsicmp(argv[1], L"--run-all-detection") == 0)
    {
        return RunMatching(false);
    }
    if (_wcsicmp(argv[1], L"--run-all-benign") == 0)
    {
        return RunMatching(true);
    }

    PrintUsage();
    return 1;
}
