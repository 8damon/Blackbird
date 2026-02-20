@echo off
setlocal

if "%VSCMD_VER%"=="" (
  echo Please run this from a "Developer Command Prompt for VS".
  exit /b 1
)

cl /nologo /W4 /WX /Zi /Od /TC stinger_client.c /link /DEBUG /INCREMENTAL:NO /OUT:stinger_client.exe
exit /b %ERRORLEVEL%
