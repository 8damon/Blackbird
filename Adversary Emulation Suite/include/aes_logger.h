#pragma once

enum class AesLogLevel
{
    Trace = 0,
    Debug,
    Info,
    Warn,
    Error,
    Off,
};

void AesLoggerInitializeFromEnvironment();
void AesLoggerShutdown();
void AesLoggerSetLevel(AesLogLevel level);
AesLogLevel AesLoggerGetLevel();
bool AesLoggerSetLevelFromString(const wchar_t* value);
bool AesLoggerOpenFile(const wchar_t* path);
void AesLoggerSetScenario(const char* scenarioName);
void AesLoggerClearScenario();
void AesLoggerLog(AesLogLevel level, const char* file, int line, const char* functionName, const char* format, ...);

#define AES_LOG_TRACE(...) AesLoggerLog(AesLogLevel::Trace, __FILE__, __LINE__, __FUNCTION__, __VA_ARGS__)
#define AES_LOG_DEBUG(...) AesLoggerLog(AesLogLevel::Debug, __FILE__, __LINE__, __FUNCTION__, __VA_ARGS__)
#define AES_LOG_INFO(...) AesLoggerLog(AesLogLevel::Info, __FILE__, __LINE__, __FUNCTION__, __VA_ARGS__)
#define AES_LOG_WARN(...) AesLoggerLog(AesLogLevel::Warn, __FILE__, __LINE__, __FUNCTION__, __VA_ARGS__)
#define AES_LOG_ERROR(...) AesLoggerLog(AesLogLevel::Error, __FILE__, __LINE__, __FUNCTION__, __VA_ARGS__)
