@echo off
REM ============================================================
REM  troubleshoot.bat
REM
REM  Purpose:
REM  Launches troubleshoot.ps1 using PowerShell with a temporary
REM  execution policy bypass. This does NOT modify the system
REM  execution policy permanently.
REM
REM  What it does:
REM  - Uses -ExecutionPolicy Bypass (process scope only)
REM  - Uses -NoProfile to avoid user profile side effects
REM  - Passes through the exit code from the PowerShell script
REM
REM  Requirements:
REM  - troubleshoot.ps1 must be in the same directory as this .bat
REM ============================================================

SET SCRIPT_DIR=%~dp0
SET SCRIPT_PATH=%SCRIPT_DIR%troubleshoot.ps1

IF NOT EXIST "%SCRIPT_PATH%" (
    echo ERROR: troubleshoot.ps1 not found in %SCRIPT_DIR%
    exit /b 1
)

echo Launching PowerShell Troubleshooter...
echo.

powershell.exe ^
    -NoProfile ^
    -ExecutionPolicy Bypass ^
    -File "%SCRIPT_PATH%"

SET EXIT_CODE=%ERRORLEVEL%

echo.
echo PowerShell exited with code %EXIT_CODE%

exit /b %EXIT_CODE%
