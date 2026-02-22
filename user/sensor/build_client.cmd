@echo off
setlocal

if "%VSCMD_VER%"=="" (
  echo Please run this from a "Developer Command Prompt for VS".
  exit /b 1
)

set ROOT=%~dp0..\..

msbuild "%ROOT%\vcxproj\StingerSensorCore.vcxproj" /p:Configuration=Debug /p:Platform=x64 /m:1
if errorlevel 1 exit /b %ERRORLEVEL%

msbuild "%ROOT%\vcxproj\StingerClient.vcxproj" /p:Configuration=Debug /p:Platform=x64 /m:1
exit /b %ERRORLEVEL%
