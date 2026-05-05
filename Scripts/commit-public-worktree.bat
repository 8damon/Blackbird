@echo off
setlocal

pushd "%~dp0\.." >nul
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Commit-PublicWorktree.ps1" %*
set EXIT_CODE=%ERRORLEVEL%
popd >nul

exit /b %EXIT_CODE%
