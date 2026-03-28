#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <iphlpapi.h>
#include <strsafe.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

struct DetectionExampleDef
{
    const char *Name;
    const char *Category;
    const char *Summary;
    const char *Expected;
    bool Benign;
    int (*Run)(int argc, wchar_t **argv);
};

void ExamplePrint(const char *format, ...);
std::wstring ExampleGetSelfPath();
bool ExampleLaunchInternalChild(const wchar_t *mode, PROCESS_INFORMATION *pi, DWORD creationFlags = CREATE_NO_WINDOW);
void ExampleCleanupProcess(PROCESS_INFORMATION *pi, bool terminate, DWORD waitMs);
DWORD ExampleFindProcessIdByName(const wchar_t *name);
int ExampleRunDirectSyscallNtQueryVm(int argc, wchar_t **argv);
int ExampleRunRemoteThread(int argc, wchar_t **argv);
int ExampleRunPpidSpoof(int argc, wchar_t **argv);
int ExampleRunNtSystemRecon(int argc, wchar_t **argv);
int ExampleRunVmCheck(int argc, wchar_t **argv);
int ExampleRunBenignLaunch(int argc, wchar_t **argv);
int ExampleRunBenignFileIo(int argc, wchar_t **argv);
int ExampleRunBenignMemory(int argc, wchar_t **argv);
int ExampleRunBenignProcessEnum(int argc, wchar_t **argv);
