# =============================================================================
# PacketCircle Installer for Windows (x86_64)
# =============================================================================
#
# This script installs the PacketCircle Wireshark plugin on Windows.
#
# What it does:
#   1. Detects your Wireshark installation and version
#   2. Determines the correct plugin API version directory (e.g., 4.6)
#   3. Creates the epan plugin directory if it doesn't exist
#   4. Copies the plugin DLL (packetcircle.dll) to the plugin directory
#
# Plugin directory locations (in order of preference):
#   - Personal:  %APPDATA%\Wireshark\plugins\<version>\epan\
#   - System:    C:\Program Files\Wireshark\plugins\<version>\epan\
#
# Requirements:
#   - Wireshark 4.x installed
#   - Windows 10/11 x86_64
#
# Usage:
#   Right-click -> "Run with PowerShell"
#   or from PowerShell: .\install.ps1
#
# To uninstall, simply delete the packetcircle.dll file from the plugin directory.
# =============================================================================

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$PluginFile = Join-Path $ScriptDir "packetcircle.dll"
$PluginName = "packetcircle.dll"

Write-Host ""
Write-Host "===========================================================" -ForegroundColor Cyan
Write-Host "      PacketCircle Installer for Windows                    " -ForegroundColor Cyan
Write-Host "      x86_64 (64-bit Intel/AMD)                            " -ForegroundColor Cyan
Write-Host "===========================================================" -ForegroundColor Cyan
Write-Host ""

# --- Step 1: Verify the plugin binary exists ---
if (-not (Test-Path $PluginFile)) {
    Write-Host "Error: $PluginName not found in $ScriptDir" -ForegroundColor Red
    Write-Host "Please ensure the plugin DLL is in the same directory as this script."
    Read-Host "Press Enter to exit"
    exit 1
}

$fileInfo = Get-Item $PluginFile
Write-Host "[OK] " -ForegroundColor Green -NoNewline
Write-Host "Found plugin binary: $PluginFile ($([math]::Round($fileInfo.Length / 1KB)) KB)"

# --- Step 2: Find Wireshark and determine version ---
$WsVersion = $null
$WiresharkPath = $null

# Check common installation paths
$searchPaths = @(
    "$env:ProgramFiles\Wireshark",
    "${env:ProgramFiles(x86)}\Wireshark",
    "$env:LOCALAPPDATA\Programs\Wireshark"
)

foreach ($path in $searchPaths) {
    if (Test-Path "$path\Wireshark.exe") {
        $WiresharkPath = $path
        break
    }
}

# Try to get version from Wireshark.exe
if ($WiresharkPath) {
    try {
        $versionInfo = (Get-Item "$WiresharkPath\Wireshark.exe").VersionInfo
        $WsVersion = "$($versionInfo.FileMajorPart).$($versionInfo.FileMinorPart).$($versionInfo.FileBuildPart)"
    } catch {}
}

# Fallback: try tshark
if (-not $WsVersion) {
    $tshark = Get-Command "tshark" -ErrorAction SilentlyContinue
    if ($tshark) {
        try {
            $output = & tshark --version 2>&1 | Select-Object -First 1
            if ($output -match '(\d+\.\d+\.\d+)') {
                $WsVersion = $Matches[1]
            }
        } catch {}
    }
}

# Fallback: try tshark from Wireshark directory
if (-not $WsVersion -and $WiresharkPath) {
    try {
        $output = & "$WiresharkPath\tshark.exe" --version 2>&1 | Select-Object -First 1
        if ($output -match '(\d+\.\d+\.\d+)') {
            $WsVersion = $Matches[1]
        }
    } catch {}
}

if (-not $WsVersion) {
    Write-Host "Warning: Could not detect Wireshark version." -ForegroundColor Yellow
    Write-Host "Please ensure Wireshark is installed."
    $input = Read-Host "Enter Wireshark major.minor version (e.g., 4.6)"
    $WsVersion = "$input.0"
}

Write-Host "[OK] " -ForegroundColor Green -NoNewline
Write-Host "Wireshark version: $WsVersion"

# Determine plugin path version from Wireshark version
$WsMajor = $WsVersion.Split('.')[0]
$WsMinor = $WsVersion.Split('.')[1]
$PluginPathId = "$WsMajor.$WsMinor"

# Look for existing plugin version directories
$foundPathId = $null

# Check system plugin directory
if ($WiresharkPath) {
    $systemPluginBase = "$WiresharkPath\plugins"
    if (Test-Path $systemPluginBase) {
        Get-ChildItem $systemPluginBase -Directory | ForEach-Object {
            if ($_.Name -match '^\d+\.\d+$') {
                $foundPathId = $_.Name
            }
        }
    }
}

# Check personal plugin directory
$personalPluginBase = "$env:APPDATA\Wireshark\plugins"
if (Test-Path $personalPluginBase) {
    Get-ChildItem $personalPluginBase -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        if ($_.Name -match '^\d+\.\d+$') {
            $foundPathId = $_.Name
        }
    }
}

if ($foundPathId) {
    $PluginPathId = $foundPathId
}

Write-Host "[OK] " -ForegroundColor Green -NoNewline
Write-Host "Plugin API version: $PluginPathId"

# --- Step 3: Choose installation directory ---
$PersonalPluginDir = "$env:APPDATA\Wireshark\plugins\$PluginPathId\epan"
$SystemPluginDir = $null
if ($WiresharkPath) {
    $SystemPluginDir = "$WiresharkPath\plugins\$PluginPathId\epan"
}

Write-Host ""
Write-Host "Where would you like to install the plugin?"
Write-Host ""
Write-Host "  1) Personal directory (recommended)" -ForegroundColor White
Write-Host "     $PersonalPluginDir" -ForegroundColor Gray
if ($SystemPluginDir) {
    Write-Host ""
    Write-Host "  2) System directory (may require admin)" -ForegroundColor White
    Write-Host "     $SystemPluginDir" -ForegroundColor Gray
}
Write-Host ""
$choice = Read-Host "Choice [1]"
if (-not $choice) { $choice = "1" }

if ($choice -eq "2" -and $SystemPluginDir) {
    $InstallDir = $SystemPluginDir
} else {
    $InstallDir = $PersonalPluginDir
}

# --- Step 4: Create directory and install ---
Write-Host ""
Write-Host "Installing to: $InstallDir" -ForegroundColor Cyan

if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
}

Copy-Item $PluginFile "$InstallDir\$PluginName" -Force

# --- Step 5: Verify installation ---
if (Test-Path "$InstallDir\$PluginName") {
    Write-Host ""
    Write-Host "===========================================================" -ForegroundColor Green
    Write-Host "      Installation successful!                              " -ForegroundColor Green
    Write-Host "===========================================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Plugin installed to:"
    Write-Host "  $InstallDir\$PluginName" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Next steps:"
    Write-Host "  1. Restart Wireshark (if running)"
    Write-Host "  2. Open a capture file or start a live capture"
    Write-Host "  3. Look for PacketCircle in the Tools menu"
    Write-Host ""
    Write-Host "  To uninstall:"
    Write-Host "  Delete: $InstallDir\$PluginName" -ForegroundColor Yellow
    Write-Host ""
} else {
    Write-Host "Error: Installation failed." -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

Read-Host "Press Enter to exit"
