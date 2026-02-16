# =============================================================================
# PacketCircle Installer for Windows (x86_64)  -  v0.3.1
# =============================================================================
#
# This script installs the PacketCircle Wireshark plugin on Windows.
#
# What it does:
#   1. Detects your Wireshark installation and version
#   2. Determines the correct plugin API version directory (e.g., 4.6)
#   3. Creates the epan plugin directory if it doesn't exist
#   4. Copies the plugin DLL (packetcircle.dll) to the plugin directory
#   5. Detects Windows 10 and provides targeted compatibility advice
#
# Plugin directory locations (in order of preference):
#   - Personal:  %APPDATA%\Wireshark\plugins\<version>\epan\
#   - System:    C:\Program Files\Wireshark\plugins\<version>\epan\
#
# Requirements:
#   - Wireshark 4.6.x installed
#   - Windows 10/11 x86_64
#
# Usage:
#   Right-click -> "Run with PowerShell"
#   or from PowerShell: .\install.ps1
#
# To uninstall, simply delete the packetcircle.dll file from the plugin directory.
# =============================================================================

$ErrorActionPreference = "Stop"

$PluginVersion = "0.3.1"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$PluginFile = Join-Path $ScriptDir "packetcircle.dll"
$PluginName = "packetcircle.dll"

Write-Host ""
Write-Host "===========================================================" -ForegroundColor Cyan
Write-Host "      PacketCircle Installer for Windows  v$PluginVersion   " -ForegroundColor Cyan
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
    Write-Host "      Installation successful!  (PacketCircle v$PluginVersion)" -ForegroundColor Green
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

    # --- Windows 10 compatibility advisory ---
    $osCaption = (Get-CimInstance Win32_OperatingSystem).Caption
    $osBuild = [System.Environment]::OSVersion.Version.Build
    $isWin10 = ($osCaption -like "*Windows 10*") -or ($osBuild -lt 22000)

    if ($isWin10) {
        Write-Host "===========================================================" -ForegroundColor Yellow
        Write-Host "  WINDOWS 10 DETECTED - Important Compatibility Notes      " -ForegroundColor Yellow
        Write-Host "===========================================================" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  PacketCircle has been tested primarily on Windows 11."
        Write-Host "  On Windows 10, the plugin may fail to load due to:"
        Write-Host ""
        Write-Host "  1. Missing or outdated VC++ Runtime (VCRUNTIME140.dll," -ForegroundColor White
        Write-Host "     VCRUNTIME140_1.dll, MSVCP140.dll)" -ForegroundColor White
        Write-Host "     -> Install the latest VC++ 2022 Redistributable (x64):" -ForegroundColor Gray
        Write-Host "        https://aka.ms/vs/17/release/vc_redist.x64.exe" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  2. Windows SmartScreen / download blocking" -ForegroundColor White
        Write-Host "     -> Right-click packetcircle.dll -> Properties -> Unblock" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  3. DLL search path differences between Win10 and Win11" -ForegroundColor White
        Write-Host "     -> Ensure Wireshark's install directory is in your PATH," -ForegroundColor Gray
        Write-Host "        or install the plugin to the system plugins folder." -ForegroundColor Gray
        Write-Host ""
        Write-Host "  4. Antivirus software silently blocking unsigned DLLs" -ForegroundColor White
        Write-Host "     -> Check your antivirus quarantine/exception list." -ForegroundColor Gray
        Write-Host ""

        # Check VC++ Runtime presence
        $vcKeyPaths = @(
            "HKLM:\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\X64",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\VisualStudio\14.0\VC\Runtimes\X64"
        )
        $vcFound = $false
        foreach ($kp in $vcKeyPaths) {
            if (Test-Path $kp) {
                try {
                    $vcVer = (Get-ItemProperty $kp -ErrorAction SilentlyContinue).Version
                    if ($vcVer) {
                        Write-Host "  [OK] VC++ Runtime detected: $vcVer" -ForegroundColor Green
                        $vcFound = $true
                        break
                    }
                } catch {}
            }
        }
        if (-not $vcFound) {
            Write-Host "  [WARN] VC++ 2022 Redistributable (x64) NOT detected!" -ForegroundColor Red
            Write-Host "         Please install it from:" -ForegroundColor Yellow
            Write-Host "         https://aka.ms/vs/17/release/vc_redist.x64.exe" -ForegroundColor Cyan
        }

        # Check for download block (Zone.Identifier)
        $installedDll = "$InstallDir\$PluginName"
        $zoneFile = "${installedDll}:Zone.Identifier"
        try {
            $zoneContent = Get-Content $zoneFile -ErrorAction SilentlyContinue
            if ($zoneContent) {
                Write-Host ""
                Write-Host "  [WARN] The DLL has an internet download marker." -ForegroundColor Yellow
                Write-Host "         Unblocking automatically..." -ForegroundColor Gray
                Unblock-File $installedDll -ErrorAction SilentlyContinue
                Write-Host "  [OK]   DLL unblocked." -ForegroundColor Green
            }
        } catch {}

        Write-Host ""
        Write-Host "  If the plugin does NOT appear in Wireshark's Tools menu" -ForegroundColor Yellow
        Write-Host "  after restarting, run the troubleshooting script:" -ForegroundColor Yellow
        Write-Host ""
        $troubleshootPath = Join-Path $ScriptDir "troubleshoot.ps1"
        if (Test-Path $troubleshootPath) {
            Write-Host "    .\troubleshoot.ps1" -ForegroundColor Cyan
        } else {
            Write-Host "    Download troubleshoot.ps1 from the tools/ directory" -ForegroundColor Cyan
            Write-Host "    in the PacketCircle repository and run it." -ForegroundColor Cyan
        }
        Write-Host ""
        Write-Host "  The troubleshooting script checks all DLL dependencies," -ForegroundColor Gray
        Write-Host "  verifies the plugin directory, tests DLL loading, detects" -ForegroundColor Gray
        Write-Host "  download blocks, and reports exactly what may be wrong." -ForegroundColor Gray
        Write-Host "  No extra software required - it runs natively in PowerShell." -ForegroundColor Gray
        Write-Host ""
    }

    Write-Host "  To uninstall:"
    Write-Host "  Delete: $InstallDir\$PluginName" -ForegroundColor Yellow
    Write-Host ""
} else {
    Write-Host "Error: Installation failed." -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

Read-Host "Press Enter to exit"
