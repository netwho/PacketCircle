@echo off
REM ============================================================
REM  install.bat
REM
REM  Purpose:
REM  Launches install.ps1 using PowerShell with a temporary
REM  execution policy bypass. This does NOT modify the system
REM  execution policy permanently.
REM
REM  What it does:
REM  - Uses -ExecutionPolicy Bypass (process scope only)
REM  - Uses -NoProfile to avoid user profile side effects
REM  - Passes through the exit code from the PowerShell script
REM
REM  Requirements:
REM  - install.ps1 must be in the same directory as this .bat
REM ============================================================

SET SCRIPT_DIR=%~dp0
SET SCRIPT_PATH=%SCRIPT_DIR%install.ps1

IF NOT EXIST "%SCRIPT_PATH%" (
    echo ERROR: install.ps1 not found in %SCRIPT_DIR%
    pause
    exit /b 1
)

echo.
echo ===========================================================
echo   PacketCircle Installer
echo ===========================================================
echo.
echo   TIP: For the best experience run this installer from
echo   an existing Command Prompt window so you can scroll
echo   back and review all prompts and options:
echo.
echo     1. Open "Command Prompt"  (search: cmd)
echo     2. cd /d "%SCRIPT_DIR%"
echo     3. install.bat
echo.
echo   Launching PowerShell installer now...
echo.

powershell.exe ^
    -NoProfile ^
    -ExecutionPolicy Bypass ^
    -File "%SCRIPT_PATH%"

SET EXIT_CODE=%ERRORLEVEL%

echo.
echo PowerShell exited with code %EXIT_CODE%
echo.
pause
exit /b %EXIT_CODE%
