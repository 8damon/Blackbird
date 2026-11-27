#include "../include/detection_examples.h"

static const AesScenarioDefinition kBenignScenarios[] = {
    {"benign-launch", "benign", "Launches a child and terminates it without suspicious cross-process behavior.",
     "No high-confidence detection expected.", true, ExampleRunBenignLaunch},
    {"benign-file-io", "benign", "Creates, writes, reads, and deletes a temporary file.",
     "No high-confidence detection expected.", true, ExampleRunBenignFileIo},
    {"benign-registry-io", "benign",
     "Creates a key, sets a value, queries it, enumerates subkeys, then deletes everything.",
     "Registry READ/WRITE/RECON/DELETE events visible in RegistryPane; no high-severity detection expected.", true,
     ExampleRunBenignRegistryIo},
    {"benign-memory", "benign", "Allocates and protects memory in the current process only.",
     "No cross-process memory detection expected.", true, ExampleRunBenignMemory},
    {"benign-process-enum", "benign", "Enumerates processes through Toolhelp snapshot APIs.",
     "No high-confidence detection expected.", true, ExampleRunBenignProcessEnum},
};

const AesModuleDefinition* AesGetBenignModule()
{
    static const AesModuleDefinition module = {
        "benign",
        "benign",
        "Baseline scenarios used to validate low-severity or no-detection behavior.",
        kBenignScenarios,
        ARRAYSIZE(kBenignScenarios),
        DetectionExamplesInternalBenignMain,
    };

    return &module;
}
