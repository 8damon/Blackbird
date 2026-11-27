#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <windows.h>
#include <tlhelp32.h>
#include <strsafe.h>

#include <cstdarg>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <string>
#include <vector>

void BkaesPrint(const char* format, ...);
void BkaesSettleTelemetry(DWORD waitMs = 1500);
std::wstring BkaesSelfPath();
std::wstring BkaesSelfDirectory();
std::wstring BkaesTempPath(const wchar_t* fileName);
bool BkaesWriteTextFile(const std::wstring& path, const char* text);
bool BkaesLaunchSelfChild(PROCESS_INFORMATION* pi, DWORD creationFlags = CREATE_NO_WINDOW);
int BkaesMaybeRunChildMode(int argc, wchar_t** argv);
void BkaesCleanupProcess(PROCESS_INFORMATION* pi, bool terminate = true, DWORD waitMs = 2500);
DWORD BkaesFindProcessIdByName(const wchar_t* imageName);
bool BkaesCreateSuspendedProcess(const std::wstring& commandLine, PROCESS_INFORMATION* pi);
void BkaesTerminateAfterCreateTelemetry(PROCESS_INFORMATION* pi);
std::vector<wchar_t> BkaesMutableCommandLine(const std::wstring& commandLine);
bool BkaesIsSensitiveEnabled(int argc, wchar_t** argv);
