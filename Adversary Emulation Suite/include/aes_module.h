#pragma once

#include <cstddef>

struct AesScenarioDefinition
{
    const char* Name;
    const char* Category;
    const char* Summary;
    const char* Expected;
    bool Benign;
    int (*Run)(int argc, wchar_t** argv);
};

struct AesModuleDefinition
{
    const char* Name;
    const char* Category;
    const char* Description;
    const AesScenarioDefinition* Scenarios;
    size_t ScenarioCount;
    int (*RunInternal)(const wchar_t* mode);
};

using DetectionExampleDef = AesScenarioDefinition;

const AesModuleDefinition* const* AesGetModules(size_t* count);
const AesScenarioDefinition* AesFindScenarioByName(const wchar_t* name, const AesModuleDefinition** module);
int AesRunInternalMode(const wchar_t* mode);

const AesModuleDefinition* AesGetDetectionModule();
const AesModuleDefinition* AesGetBenignModule();
