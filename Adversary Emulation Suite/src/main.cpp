#include "../include/detection_examples.h"

#include <vector>

static bool ConfigureLoggingFromArgs(int argc, wchar_t** argv, std::vector<wchar_t*>& filteredArgs)
{
    static const wchar_t kLogLevelPrefix[] = L"--log-level=";
    static const wchar_t kLogFilePrefix[] = L"--log-file=";

    filteredArgs.clear();
    if (argc > 0)
    {
        filteredArgs.push_back(argv[0]);
    }

    for (int i = 1; i < argc; ++i)
    {
        if (_wcsicmp(argv[i], L"--log-level") == 0)
        {
            if (i + 1 >= argc)
            {
                ExamplePrint("Missing value for --log-level\n");
                return false;
            }
            if (!AesLoggerSetLevelFromString(argv[i + 1]))
            {
                ExamplePrint("Invalid log level: %ls\n", argv[i + 1]);
                return false;
            }
            SetEnvironmentVariableW(L"AES_LOG_LEVEL", argv[i + 1]);
            ++i;
            continue;
        }
        if (wcsncmp(argv[i], kLogLevelPrefix, wcslen(kLogLevelPrefix)) == 0)
        {
            const wchar_t* level = argv[i] + wcslen(kLogLevelPrefix);
            if (!AesLoggerSetLevelFromString(level))
            {
                ExamplePrint("Invalid log level: %ls\n", level);
                return false;
            }
            SetEnvironmentVariableW(L"AES_LOG_LEVEL", level);
            continue;
        }
        if (_wcsicmp(argv[i], L"--log-file") == 0)
        {
            if (i + 1 >= argc)
            {
                ExamplePrint("Missing value for --log-file\n");
                return false;
            }
            if (!AesLoggerOpenFile(argv[i + 1]))
            {
                ExamplePrint("Failed to open log file: %ls\n", argv[i + 1]);
                return false;
            }
            SetEnvironmentVariableW(L"AES_LOG_FILE", argv[i + 1]);
            ++i;
            continue;
        }
        if (wcsncmp(argv[i], kLogFilePrefix, wcslen(kLogFilePrefix)) == 0)
        {
            const wchar_t* path = argv[i] + wcslen(kLogFilePrefix);
            if (!AesLoggerOpenFile(path))
            {
                ExamplePrint("Failed to open log file: %ls\n", path);
                return false;
            }
            SetEnvironmentVariableW(L"AES_LOG_FILE", path);
            continue;
        }

        filteredArgs.push_back(argv[i]);
    }

    return true;
}

static void PrintUsage()
{
    ExamplePrint("DetectionExamples usage:\n");
    ExamplePrint("  DetectionExamples.exe --list\n");
    ExamplePrint("  DetectionExamples.exe --run <name>\n");
    ExamplePrint("  DetectionExamples.exe --run-all-detection\n");
    ExamplePrint("  DetectionExamples.exe --run-all-benign\n");
    ExamplePrint("  DetectionExamples.exe [--log-level trace|debug|info|warn|error|off] [--log-file <path>] ...\n");
}

static void PrintScenarioList()
{
    size_t moduleCount = 0;
    const AesModuleDefinition* const* modules = AesGetModules(&moduleCount);
    size_t ordinal = 1;

    ExamplePrint("\nAvailable scenarios:\n");
    for (size_t i = 0; i < moduleCount; ++i)
    {
        const AesModuleDefinition* module = modules[i];
        if (module == nullptr)
        {
            continue;
        }

        ExamplePrint("\n%s module:\n", module->Name);
        for (size_t j = 0; j < module->ScenarioCount; ++j)
        {
            const auto& example = module->Scenarios[j];
            ExamplePrint("  %2zu. %-22s [%s] %s\n", ordinal, example.Name, example.Category, example.Expected);
            ordinal += 1;
        }
    }
}

static const AesScenarioDefinition* GetScenarioByOrdinal(size_t ordinal, const AesModuleDefinition** selectedModule)
{
    size_t moduleCount = 0;
    const AesModuleDefinition* const* modules = AesGetModules(&moduleCount);
    size_t current = 1;

    if (selectedModule != nullptr)
    {
        *selectedModule = nullptr;
    }

    for (size_t i = 0; i < moduleCount; ++i)
    {
        const AesModuleDefinition* module = modules[i];
        if (module == nullptr)
        {
            continue;
        }

        for (size_t j = 0; j < module->ScenarioCount; ++j)
        {
            if (current == ordinal)
            {
                if (selectedModule != nullptr)
                {
                    *selectedModule = module;
                }
                return &module->Scenarios[j];
            }
            current += 1;
        }
    }

    return nullptr;
}

static size_t GetScenarioCount()
{
    size_t moduleCount = 0;
    const AesModuleDefinition* const* modules = AesGetModules(&moduleCount);
    size_t scenarioCount = 0;

    for (size_t i = 0; i < moduleCount; ++i)
    {
        if (modules[i] != nullptr)
        {
            scenarioCount += modules[i]->ScenarioCount;
        }
    }

    return scenarioCount;
}

static void WaitForEnter()
{
    ExamplePrint("\nPress Enter to continue...");
    fflush(stdout);
    (void)getchar();
}

static int RunScenario(const AesScenarioDefinition* example, int argc, wchar_t** argv)
{
    int rc;

    if (example == nullptr || example->Run == nullptr)
    {
        AES_LOG_ERROR("RunScenario received an invalid scenario");
        return 1;
    }

    AesLoggerSetScenario(example->Name);
    AES_LOG_INFO("Starting scenario category=%s benign=%d argc=%d", example->Category, example->Benign ? 1 : 0, argc);
    rc = example->Run(argc, argv);
    if (rc == 0)
    {
        AES_LOG_INFO("Scenario completed successfully rc=%d", rc);
    }
    else
    {
        AES_LOG_ERROR("Scenario failed rc=%d", rc);
    }
    AesLoggerClearScenario();
    return rc;
}

static int RunMatching(bool benign)
{
    size_t moduleCount = 0;
    const AesModuleDefinition* const* modules = AesGetModules(&moduleCount);
    int failures = 0;

    AES_LOG_INFO("Running scenarios by benign=%d moduleCount=%zu", benign ? 1 : 0, moduleCount);
    for (size_t i = 0; i < moduleCount; ++i)
    {
        const AesModuleDefinition* module = modules[i];
        if (module == nullptr)
        {
            continue;
        }

        for (size_t j = 0; j < module->ScenarioCount; ++j)
        {
            const auto& example = module->Scenarios[j];
            if (example.Benign != benign)
            {
                continue;
            }

            ExamplePrint("\n[%s] %s\n", example.Benign ? "BENIGN" : "DETECTION", example.Name);
            ExamplePrint("  summary : %s\n", example.Summary);
            ExamplePrint("  expected: %s\n", example.Expected);
            if (RunScenario(&example, 0, nullptr) != 0)
            {
                failures += 1;
            }
        }
    }

    AES_LOG_INFO("Finished scenario group benign=%d failures=%d", benign ? 1 : 0, failures);
    return failures == 0 ? 0 : 1;
}

static int RunInteractiveMenu()
{
    char input[32];

    for (;;)
    {
        int selection = 0;
        const size_t scenarioCount = GetScenarioCount();
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
            AES_LOG_INFO("Interactive menu input closed");
            return 0;
        }

        if ((input[0] == 'q') || (input[0] == 'Q'))
        {
            AES_LOG_INFO("Interactive menu quit selected");
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
        if (selection < 1 || selection > (int)scenarioCount)
        {
            ExamplePrint("\nInvalid selection.\n");
            AES_LOG_WARN("Invalid interactive selection=%d scenarioCount=%zu", selection, scenarioCount);
            WaitForEnter();
            continue;
        }

        {
            const AesScenarioDefinition* example = GetScenarioByOrdinal((size_t)selection, nullptr);
            ExamplePrint("\n[%s] %s\n", example->Benign ? "BENIGN" : "DETECTION", example->Name);
            ExamplePrint("  summary : %s\n", example->Summary);
            ExamplePrint("  expected: %s\n", example->Expected);
            (void)RunScenario(example, 0, nullptr);
        }
        WaitForEnter();
    }
}

int wmain(int argc, wchar_t** argv)
{
    std::vector<wchar_t*> filteredArgs;

    AesLoggerInitializeFromEnvironment();
    if (!ConfigureLoggingFromArgs(argc, argv, filteredArgs))
    {
        AesLoggerShutdown();
        return 1;
    }

    argc = (int)filteredArgs.size();
    argv = filteredArgs.data();

    AES_LOG_INFO("Application start argc=%d", argc);
    if (argc >= 3 && _wcsicmp(argv[1], L"--internal") == 0)
    {
        int rc;
        AesLoggerSetScenario("internal");
        rc = AesRunInternalMode(argv[2]);
        AesLoggerClearScenario();
        AesLoggerShutdown();
        return rc >= 0 ? rc : 1;
    }

    if (argc < 2)
    {
        int rc = RunInteractiveMenu();
        AesLoggerShutdown();
        return rc;
    }

    if (_wcsicmp(argv[1], L"--list") == 0)
    {
        PrintUsage();
        PrintScenarioList();
        AesLoggerShutdown();
        return 0;
    }

    if (_wcsicmp(argv[1], L"--run") == 0)
    {
        const AesScenarioDefinition* example;
        if (argc < 3)
        {
            PrintUsage();
            AesLoggerShutdown();
            return 1;
        }
        example = AesFindScenarioByName(argv[2], nullptr);
        if (example == nullptr)
        {
            ExamplePrint("Unknown scenario: %ls\n", argv[2]);
            AesLoggerShutdown();
            return 1;
        }
        ExamplePrint("[%s] %s\n", example->Benign ? "BENIGN" : "DETECTION", example->Name);
        ExamplePrint("  summary : %s\n", example->Summary);
        ExamplePrint("  expected: %s\n", example->Expected);
        {
            int rc = RunScenario(example, argc - 2, argv + 2);
            AesLoggerShutdown();
            return rc;
        }
    }

    if (_wcsicmp(argv[1], L"--run-all-detection") == 0)
    {
        int rc = RunMatching(false);
        AesLoggerShutdown();
        return rc;
    }
    if (_wcsicmp(argv[1], L"--run-all-benign") == 0)
    {
        int rc = RunMatching(true);
        AesLoggerShutdown();
        return rc;
    }

    PrintUsage();
    AesLoggerShutdown();
    return 1;
}
