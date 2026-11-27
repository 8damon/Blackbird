#include "../include/detection_examples.h"

const AesModuleDefinition* const* AesGetModules(size_t* count)
{
    static const AesModuleDefinition* modules[] = {
        // Add new module providers here; the CLI discovers scenarios through this list.
        AesGetDetectionModule(),
        AesGetBenignModule(),
    };

    if (count != nullptr)
    {
        *count = ARRAYSIZE(modules);
    }

    return modules;
}

const AesScenarioDefinition* AesFindScenarioByName(const wchar_t* name, const AesModuleDefinition** module)
{
    char narrow[128];
    size_t moduleCount = 0;
    const AesModuleDefinition* const* modules;

    if (module != nullptr)
    {
        *module = nullptr;
    }
    if (name == nullptr)
    {
        return nullptr;
    }
    if (WideCharToMultiByte(CP_UTF8, 0, name, -1, narrow, ARRAYSIZE(narrow), nullptr, nullptr) == 0)
    {
        AES_LOG_ERROR("Failed to convert scenario name from wide string err=%lu", GetLastError());
        return nullptr;
    }

    modules = AesGetModules(&moduleCount);
    for (size_t i = 0; i < moduleCount; ++i)
    {
        const AesModuleDefinition* currentModule = modules[i];
        if (currentModule == nullptr)
        {
            continue;
        }

        for (size_t j = 0; j < currentModule->ScenarioCount; ++j)
        {
            const AesScenarioDefinition* scenario = &currentModule->Scenarios[j];
            if (_stricmp(scenario->Name, narrow) == 0)
            {
                if (module != nullptr)
                {
                    *module = currentModule;
                }
                AES_LOG_DEBUG("Resolved scenario name=%s module=%s", scenario->Name, currentModule->Name);
                return scenario;
            }
        }
    }

    AES_LOG_WARN("Scenario not found name=%s", narrow);
    return nullptr;
}

int AesRunInternalMode(const wchar_t* mode)
{
    size_t moduleCount = 0;
    const AesModuleDefinition* const* modules = AesGetModules(&moduleCount);

    if (mode == nullptr)
    {
        AES_LOG_ERROR("Internal mode dispatch received null mode");
        return -1;
    }

    AES_LOG_DEBUG("Dispatching internal mode=%ls moduleCount=%zu", mode, moduleCount);
    for (size_t i = 0; i < moduleCount; ++i)
    {
        const AesModuleDefinition* module = modules[i];
        int rc;

        if (module == nullptr || module->RunInternal == nullptr)
        {
            continue;
        }

        rc = module->RunInternal(mode);
        if (rc >= 0)
        {
            AES_LOG_DEBUG("Internal mode=%ls handledBy=%s rc=%d", mode, module->Name, rc);
            return rc;
        }
    }

    AES_LOG_WARN("Unhandled internal mode=%ls", mode);
    return -1;
}
