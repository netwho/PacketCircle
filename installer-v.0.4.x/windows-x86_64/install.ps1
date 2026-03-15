# =============================================================================
# PacketCircle Installer for Windows (x86_64)
# =============================================================================
#
# Supports:
#   - Installing v.0.3.2 or v.0.4.4 (default: latest)
#   - Detecting an already-installed version
#   - Upgrading, downgrading, and uninstalling
#
# Plugin directory:
#   Personal:  %APPDATA%\Wireshark\plugins\<version>\epan\
#   System:    C:\Program Files\Wireshark\plugins\<version>\epan\
#
# Usage:
#   Right-click -> "Run with PowerShell"
#   or: .\install.ps1
# =============================================================================

$ErrorActionPreference = "Stop"

$ScriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$PluginName = "packetcircle.dll"

Write-Host ""
Write-Host "===========================================================" -ForegroundColor Cyan
Write-Host "      PacketCircle Installer for Windows                   " -ForegroundColor Cyan
Write-Host "      x86_64 (64-bit Intel/AMD)                            " -ForegroundColor Cyan
Write-Host "      Available: v.0.3.2, v.0.4.4 (latest)               " -ForegroundColor Cyan
Write-Host "===========================================================" -ForegroundColor Cyan
Write-Host ""

# --- Warn if launched directly (e.g. double-click) instead of from a Command Prompt ---
$parentProcess = (Get-CimInstance Win32_Process -Filter "ProcessId=$PID" -ErrorAction SilentlyContinue).ParentProcessId
$parentName    = (Get-Process -Id $parentProcess -ErrorAction SilentlyContinue).ProcessName
if ($parentName -notmatch '^(cmd|powershell|pwsh|WindowsTerminal)$') {
    Write-Host "  !! IMPORTANT: Run this installer from a Command Prompt window !!" -ForegroundColor Red
    Write-Host "     If you double-clicked this file you may miss interactive"      -ForegroundColor Yellow
    Write-Host "     prompts and the window may close before you can read them."    -ForegroundColor Yellow
    Write-Host ""
    Write-Host "     How to run correctly:"                                          -ForegroundColor White
    Write-Host "       1. Open Command Prompt  (search: cmd)"                       -ForegroundColor White
    Write-Host "       2. cd /d `"$ScriptDir`""                                     -ForegroundColor White
    Write-Host "       3. install.bat"                                               -ForegroundColor White
    Write-Host ""
    Write-Host "     Continuing anyway in 5 seconds..." -ForegroundColor Yellow
    Start-Sleep -Seconds 5
    Write-Host ""
}


# --- Verify binaries exist ---
foreach ($ver in @("v.0.3.2", "v.0.4.4")) {
    $path = Join-Path $ScriptDir "$ver\$PluginName"
    if (-not (Test-Path $path)) {
        Write-Host "Error: Missing binary: $ver\$PluginName" -ForegroundColor Red
        Read-Host "Press Enter to exit"; exit 1
    }
}
Write-Host "[OK] " -ForegroundColor Green -NoNewline
Write-Host "All plugin binaries present."

# --- Detect Wireshark ---
$WsVersion     = $null
$WiresharkPath = $null

foreach ($path in @(
    "$env:ProgramFiles\Wireshark",
    "${env:ProgramFiles(x86)}\Wireshark",
    "$env:LOCALAPPDATA\Programs\Wireshark"
)) {
    if (Test-Path "$path\Wireshark.exe") { $WiresharkPath = $path; break }
}

if ($WiresharkPath) {
    try {
        $vi = (Get-Item "$WiresharkPath\Wireshark.exe").VersionInfo
        $WsVersion = "$($vi.FileMajorPart).$($vi.FileMinorPart).$($vi.FileBuildPart)"
    } catch {}
}

if (-not $WsVersion) {
    $tshark = Get-Command "tshark" -ErrorAction SilentlyContinue
    if ($tshark) {
        try {
            $out = & tshark --version 2>&1 | Select-Object -First 1
            if ($out -match '(\d+\.\d+\.\d+)') { $WsVersion = $Matches[1] }
        } catch {}
    }
}

if (-not $WsVersion -and $WiresharkPath) {
    try {
        $out = & "$WiresharkPath\tshark.exe" --version 2>&1 | Select-Object -First 1
        if ($out -match '(\d+\.\d+\.\d+)') { $WsVersion = $Matches[1] }
    } catch {}
}

if (-not $WsVersion) {
    Write-Host "Warning: Could not detect Wireshark version." -ForegroundColor Yellow
    $inp = Read-Host "Enter Wireshark major.minor version (e.g., 4.6)"
    $WsVersion = "$inp.0"
}

$WsMajor      = $WsVersion.Split('.')[0]
$WsMinor      = $WsVersion.Split('.')[1]
$PluginPathId = "$WsMajor.$WsMinor"   # default; overridden below if we find the real dir

# --- Determine plugin directory ---
# Scan known locations to find the exact directory name Wireshark uses for this version.
# Windows typically uses dots ("4.6") but we also handle dashes ("4-6") for safety.
$foundPathId = $null

$searchBases = @(
    $(if ($WiresharkPath) { "$WiresharkPath\plugins" } else { $null }),
    "$env:APPDATA\Wireshark\plugins",
    "$env:LOCALAPPDATA\Wireshark\plugins"
) | Where-Object { $_ -and (Test-Path $_) }

foreach ($base in $searchBases) {
    Get-ChildItem $base -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        # Match only the directory whose major.minor matches the detected version
        if ($_.Name -match "^$WsMajor[\.\-]$WsMinor$") {
            $foundPathId = $_.Name
        }
    }
    if ($foundPathId) { break }
}

if ($foundPathId) {
    $PluginPathId = $foundPathId
    Write-Host "  Plugin path ID detected: " -NoNewline
    Write-Host $PluginPathId -ForegroundColor Cyan
} else {
    Write-Host "  Plugin path ID not found in existing dirs, using default: " -NoNewline
    Write-Host $PluginPathId -ForegroundColor Yellow
    Write-Host "  If the plugin does not load, check: Help > About Wireshark > Folders > Personal Plugins" -ForegroundColor Yellow
}

$PersonalPluginDir = "$env:APPDATA\Wireshark\plugins\$PluginPathId\epan"
$SystemPluginDir   = if ($WiresharkPath) { "$WiresharkPath\plugins\$PluginPathId\epan" } else { $null }

Write-Host "[OK] " -ForegroundColor Green -NoNewline
Write-Host "Wireshark version: $WsVersion  |  Plugin API: $PluginPathId"

# --- Detect currently installed version ---
# Check all known locations, including %LOCALAPPDATA% as an alternative personal dir.
$InstalledVersion = $null
$InstalledPath    = $null

$allCheckDirs = @(
    $PersonalPluginDir,
    "$env:LOCALAPPDATA\Wireshark\plugins\$PluginPathId\epan",
    $SystemPluginDir
) | Where-Object { $_ }

foreach ($dir in $allCheckDirs) {
    if (Test-Path "$dir\$PluginName") {
        $InstalledPath = "$dir\$PluginName"
        try {
            $bytes = [System.IO.File]::ReadAllBytes($InstalledPath)
            $text  = [System.Text.Encoding]::ASCII.GetString($bytes)
            if ($text -match 'PacketCircle v\.(\d+\.\d+\.\d+)') {
                $InstalledVersion = $Matches[1]
            }
        } catch {}
        break
    }
}

if ($InstalledVersion) {
    Write-Host "[OK] " -ForegroundColor Green -NoNewline
    Write-Host "Currently installed: " -NoNewline
    Write-Host "v.$InstalledVersion" -ForegroundColor Cyan
    Write-Host "  Location: $InstalledPath" -ForegroundColor Gray
} else {
    Write-Host "  No existing installation found." -ForegroundColor Gray
}

# --- Main menu ---
Write-Host ""
Write-Host "What would you like to do?"
Write-Host ""
Write-Host "  i) Install / upgrade / downgrade" -ForegroundColor Green
Write-Host "  u) Uninstall"                      -ForegroundColor Red
Write-Host "  q) Quit"                            -ForegroundColor Yellow
Write-Host ""
$action = Read-Host "Choice [i]"
if (-not $action) { $action = "i" }

switch ($action.ToLower()) {
    "u" {
        if (-not $InstalledPath) {
            Write-Host "`nPacketCircle is not currently installed." -ForegroundColor Yellow
            Read-Host "Press Enter to exit"; exit 0
        }
        Write-Host "`nRemove: $InstalledPath" -ForegroundColor Cyan
        $confirm = Read-Host "Confirm uninstall? [y/N]"
        if ($confirm -eq "y" -or $confirm -eq "Y") {
            Remove-Item $InstalledPath -Force
            Write-Host "`nPacketCircle v.$InstalledVersion uninstalled successfully." -ForegroundColor Green
        } else {
            Write-Host "Uninstall cancelled."
        }
        Read-Host "Press Enter to exit"; exit 0
    }
    "q" { Write-Host "Bye."; Read-Host "Press Enter to exit"; exit 0 }
    { $_ -eq "i" -or $_ -eq "" } { }
    default {
        Write-Host "Invalid choice." -ForegroundColor Red
        Read-Host "Press Enter to exit"; exit 1
    }
}

# --- Version selection (context-aware) ---
Write-Host ""
Write-Host "Select version to install:"
Write-Host ""

if ($InstalledVersion -eq "0.4.4") {
    Write-Host "  1) v.0.4.4 (latest)   - already installed, reinstall" -ForegroundColor Green
    Write-Host "  2) v.0.3.2             - downgrade (legacy)"           -ForegroundColor Yellow
} elseif ($InstalledVersion -eq "0.3.2") {
    Write-Host "  1) v.0.4.4 (latest)   - upgrade (recommended)"         -ForegroundColor Green
    Write-Host "  2) v.0.3.2             - already installed, reinstall"  -ForegroundColor Yellow
} else {
    Write-Host "  1) v.0.4.4 (latest)   - keyword search, display filter delegation" -ForegroundColor Green
    Write-Host "  2) v.0.3.2             - TCP stream stats, Select Results, theme-aware UI" -ForegroundColor Yellow
}

Write-Host ""
$verChoice = Read-Host "Choice [1]"
if (-not $verChoice) { $verChoice = "1" }

switch ($verChoice) {
    "1" { $SelectedVersion = "0.4.4" }
    "2" { $SelectedVersion = "0.3.2" }
    default {
        Write-Host "Invalid choice." -ForegroundColor Red
        Read-Host "Press Enter to exit"; exit 1
    }
}

$PluginFile = Join-Path $ScriptDir "v.$SelectedVersion\$PluginName"
if (-not (Test-Path $PluginFile)) {
    Write-Host "Error: Binary not found: $PluginFile" -ForegroundColor Red
    Read-Host "Press Enter to exit"; exit 1
}

$fileInfo = Get-Item $PluginFile
Write-Host ""
Write-Host "[OK] " -ForegroundColor Green -NoNewline
Write-Host "Selected: PacketCircle v.$SelectedVersion ($([math]::Round($fileInfo.Length / 1KB)) KB)"

# --- Choose install location ---
Write-Host ""
Write-Host "Where would you like to install?"
Write-Host ""
Write-Host "  1) Personal directory (recommended)" -ForegroundColor White
Write-Host "     $PersonalPluginDir"               -ForegroundColor Gray
if ($SystemPluginDir) {
    Write-Host ""
    Write-Host "  2) System directory (may require admin)" -ForegroundColor White
    Write-Host "     $SystemPluginDir"                    -ForegroundColor Gray
}
Write-Host ""
$locChoice = Read-Host "Choice [1]"
if (-not $locChoice) { $locChoice = "1" }

$InstallDir = if ($locChoice -eq "2" -and $SystemPluginDir) { $SystemPluginDir } else { $PersonalPluginDir }

# --- Install ---
Write-Host ""
Write-Host "Installing to: $InstallDir" -ForegroundColor Cyan

if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
}
Copy-Item $PluginFile "$InstallDir\$PluginName" -Force

# Unblock if downloaded from internet
try { Unblock-File "$InstallDir\$PluginName" -ErrorAction SilentlyContinue } catch {}

# --- Verify ---
if (Test-Path "$InstallDir\$PluginName") {
    Write-Host ""
    Write-Host "===========================================================" -ForegroundColor Green
    Write-Host "      Installation successful!" -ForegroundColor Green
    Write-Host "===========================================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Installed:  PacketCircle v.$SelectedVersion" -ForegroundColor Cyan
    Write-Host "  Location:   $InstallDir\$PluginName"
    Write-Host ""
    Write-Host "  Next steps:"
    Write-Host "  1. Restart Wireshark (if running)"
    Write-Host "  2. Open a capture or start a live capture"
    Write-Host "  3. Look for PacketCircle in the Tools menu"
    Write-Host ""

    # --- Windows 10 advisory ---
    $osBuild = [System.Environment]::OSVersion.Version.Build
    if ($osBuild -lt 22000) {
        Write-Host "===========================================================" -ForegroundColor Yellow
        Write-Host "  WINDOWS 10 DETECTED - Important Compatibility Notes      " -ForegroundColor Yellow
        Write-Host "===========================================================" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  1. Ensure VC++ 2022 Redistributable (x64) is installed:" -ForegroundColor White
        Write-Host "     https://aka.ms/vs/17/release/vc_redist.x64.exe"        -ForegroundColor Cyan
        Write-Host "  2. Right-click packetcircle.dll -> Properties -> Unblock"  -ForegroundColor White
        Write-Host "  3. If still failing, run: .\troubleshoot.ps1"              -ForegroundColor White
        Write-Host ""

        $vcFound = $false
        foreach ($kp in @(
            "HKLM:\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\X64",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\VisualStudio\14.0\VC\Runtimes\X64"
        )) {
            if (Test-Path $kp) {
                try {
                    $vcVer = (Get-ItemProperty $kp -ErrorAction SilentlyContinue).Version
                    if ($vcVer) {
                        Write-Host "  [OK] VC++ Runtime detected: $vcVer" -ForegroundColor Green
                        $vcFound = $true; break
                    }
                } catch {}
            }
        }
        if (-not $vcFound) {
            Write-Host "  [WARN] VC++ 2022 Redistributable (x64) NOT detected!" -ForegroundColor Red
            Write-Host "         Install from: https://aka.ms/vs/17/release/vc_redist.x64.exe" -ForegroundColor Yellow
        }
        Write-Host ""
    }

    Write-Host "  To uninstall, run this script again and choose 'u'."
    Write-Host ""
} else {
    Write-Host "Error: Installation failed." -ForegroundColor Red
    Read-Host "Press Enter to exit"; exit 1
}

Read-Host "Press Enter to exit"
