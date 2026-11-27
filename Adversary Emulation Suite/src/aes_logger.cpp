#include "../include/aes_logger.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <cstdarg>
#include <cstdio>
#include <cwchar>
#include <mutex>
#include <string>

static std::mutex g_LogLock;
static AesLogLevel g_MinLevel = AesLogLevel::Debug;
static FILE* g_LogFile = nullptr;
static bool g_ConsoleEnabled = true;
static std::string g_ScenarioName;

static const char* AesLogLevelName(AesLogLevel level)
{
    switch (level)
    {
    case AesLogLevel::Trace:
        return "TRACE";
    case AesLogLevel::Debug:
        return "DEBUG";
    case AesLogLevel::Info:
        return "INFO";
    case AesLogLevel::Warn:
        return "WARN";
    case AesLogLevel::Error:
        return "ERROR";
    case AesLogLevel::Off:
        return "OFF";
    default:
        return "UNKNOWN";
    }
}

static const char* AesBaseName(const char* path)
{
    const char* base = path;

    if (path == nullptr)
    {
        return "";
    }

    for (const char* p = path; *p != '\0'; ++p)
    {
        if (*p == '\\' || *p == '/')
        {
            base = p + 1;
        }
    }
    return base;
}

static bool AesParseBooleanFalse(const wchar_t* value)
{
    return value != nullptr && (_wcsicmp(value, L"0") == 0 || _wcsicmp(value, L"false") == 0 ||
                                _wcsicmp(value, L"no") == 0 || _wcsicmp(value, L"off") == 0);
}

void AesLoggerInitializeFromEnvironment()
{
    wchar_t value[MAX_PATH * 2];
    DWORD len;

    len = GetEnvironmentVariableW(L"AES_LOG_LEVEL", value, ARRAYSIZE(value));
    if (len > 0 && len < ARRAYSIZE(value))
    {
        (void)AesLoggerSetLevelFromString(value);
    }

    len = GetEnvironmentVariableW(L"AES_LOG_FILE", value, ARRAYSIZE(value));
    if (len > 0 && len < ARRAYSIZE(value))
    {
        (void)AesLoggerOpenFile(value);
    }

    len = GetEnvironmentVariableW(L"AES_LOG_CONSOLE", value, ARRAYSIZE(value));
    if (len > 0 && len < ARRAYSIZE(value) && AesParseBooleanFalse(value))
    {
        std::lock_guard<std::mutex> guard(g_LogLock);
        g_ConsoleEnabled = false;
    }
}

void AesLoggerShutdown()
{
    std::lock_guard<std::mutex> guard(g_LogLock);
    if (g_LogFile != nullptr)
    {
        fclose(g_LogFile);
        g_LogFile = nullptr;
    }
}

void AesLoggerSetLevel(AesLogLevel level)
{
    std::lock_guard<std::mutex> guard(g_LogLock);
    g_MinLevel = level;
}

AesLogLevel AesLoggerGetLevel()
{
    std::lock_guard<std::mutex> guard(g_LogLock);
    return g_MinLevel;
}

bool AesLoggerSetLevelFromString(const wchar_t* value)
{
    if (value == nullptr)
    {
        return false;
    }

    if (_wcsicmp(value, L"trace") == 0)
    {
        AesLoggerSetLevel(AesLogLevel::Trace);
        return true;
    }
    if (_wcsicmp(value, L"debug") == 0)
    {
        AesLoggerSetLevel(AesLogLevel::Debug);
        return true;
    }
    if (_wcsicmp(value, L"info") == 0)
    {
        AesLoggerSetLevel(AesLogLevel::Info);
        return true;
    }
    if (_wcsicmp(value, L"warn") == 0 || _wcsicmp(value, L"warning") == 0)
    {
        AesLoggerSetLevel(AesLogLevel::Warn);
        return true;
    }
    if (_wcsicmp(value, L"error") == 0)
    {
        AesLoggerSetLevel(AesLogLevel::Error);
        return true;
    }
    if (_wcsicmp(value, L"off") == 0 || _wcsicmp(value, L"none") == 0)
    {
        AesLoggerSetLevel(AesLogLevel::Off);
        return true;
    }

    return false;
}

bool AesLoggerOpenFile(const wchar_t* path)
{
    FILE* file = nullptr;

    if (path == nullptr || path[0] == L'\0')
    {
        return false;
    }

    if (_wfopen_s(&file, path, L"a") != 0 || file == nullptr)
    {
        return false;
    }

    std::lock_guard<std::mutex> guard(g_LogLock);
    if (g_LogFile != nullptr)
    {
        fclose(g_LogFile);
    }
    g_LogFile = file;
    return true;
}

void AesLoggerSetScenario(const char* scenarioName)
{
    std::lock_guard<std::mutex> guard(g_LogLock);
    g_ScenarioName = scenarioName != nullptr ? scenarioName : "";
}

void AesLoggerClearScenario()
{
    std::lock_guard<std::mutex> guard(g_LogLock);
    g_ScenarioName.clear();
}

void AesLoggerLog(AesLogLevel level, const char* file, int line, const char* functionName, const char* format, ...)
{
    char message[4096];
    SYSTEMTIME now;
    va_list args;
    DWORD pid;
    DWORD tid;

    if (static_cast<int>(level) < static_cast<int>(AesLoggerGetLevel()) || level == AesLogLevel::Off)
    {
        return;
    }

    va_start(args, format);
    (void)vsnprintf(message, sizeof(message), format, args);
    va_end(args);
    message[sizeof(message) - 1] = '\0';

    GetLocalTime(&now);
    pid = GetCurrentProcessId();
    tid = GetCurrentThreadId();

    std::lock_guard<std::mutex> guard(g_LogLock);
    FILE* targets[] = {g_ConsoleEnabled ? stderr : nullptr, g_LogFile};
    for (FILE* target : targets)
    {
        if (target == nullptr)
        {
            continue;
        }

        fprintf(target, "%04hu-%02hu-%02hu %02hu:%02hu:%02hu.%03hu [%s] pid=%lu tid=%lu", now.wYear, now.wMonth,
                now.wDay, now.wHour, now.wMinute, now.wSecond, now.wMilliseconds, AesLogLevelName(level),
                static_cast<unsigned long>(pid), static_cast<unsigned long>(tid));
        if (!g_ScenarioName.empty())
        {
            fprintf(target, " scenario=%s", g_ScenarioName.c_str());
        }
        fprintf(target, " %s:%d %s - %s\n", AesBaseName(file), line, functionName != nullptr ? functionName : "",
                message);
        fflush(target);
    }
}
