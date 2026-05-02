# =============================================================================
# PacketCircle Installer for Windows (x86_64)
# =============================================================================
#
# Supports:
#   - Installing v.0.5.2 (latest) or v.0.4.7 (stable legacy)
#   - Two flavors: Standard (default) or Experimental (enables Graph View)
#   - Detecting an already-installed version
#   - Upgrading, downgrading, and uninstalling
#
# Plugin directory:
#   Personal:  %APPDATA%\Wireshark\plugins\<version>\epan\
#   System:    C:\Program Files\Wireshark\plugins\<version>\epan\
#
# Settings file (for Experimental opt-in):
#   %USERPROFILE%\.PacketCircle\settings.ini
#
# Usage:
#   Run install.bat   (recommended — keeps the window open)
#   or: .\install.ps1
# =============================================================================

$ErrorActionPreference = "Stop"

$ScriptDir      = Split-Path -Parent $MyInvocation.MyCommand.Path
$PluginName     = "packetcircle.dll"
$LatestVersion  = "0.5.2"
$LegacyVersion  = "0.4.7"

Write-Host ""
Write-Host "===========================================================" -ForegroundColor Cyan
Write-Host "      PacketCircle Installer for Windows                   " -ForegroundColor Cyan
Write-Host "      x86_64 (64-bit Intel/AMD)                            " -ForegroundColor Cyan
Write-Host "      Available: v.0.5.2 (latest), v.0.4.7                " -ForegroundColor Cyan
Write-Host "===========================================================" -ForegroundColor Cyan
Write-Host ""

# --- Warn if launched directly (e.g. double-click) ---
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

# =============================================================================
# PREREQUISITES CHECK
# =============================================================================
Write-Host "Checking prerequisites..." -ForegroundColor White
Write-Host ""

# --- OS Detection ---
$osBuild = [System.Environment]::OSVersion.Version.Build
$osName  = if ($osBuild -ge 22000) { "Windows 11" } elseif ($osBuild -ge 10240) { "Windows 10" } else { "Windows (older)" }
$osArch  = if ([System.Environment]::Is64BitOperatingSystem) { "x86_64 (64-bit)" } else { "x86 (32-bit)" }
Write-Host "  OS              : " -NoNewline; Write-Host "$osName  build $osBuild  $osArch" -ForegroundColor Cyan
if (-not [System.Environment]::Is64BitOperatingSystem) {
    Write-Host "  [WARN] This installer is for 64-bit Windows only." -ForegroundColor Red
}

# --- VC++ Runtime ---
$vcFound   = $false
$vcVersion = $null
foreach ($kp in @(
    "HKLM:\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\X64",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\VisualStudio\14.0\VC\Runtimes\X64"
)) {
    if (Test-Path $kp) {
        try {
            $vcVersion = (Get-ItemProperty $kp -ErrorAction SilentlyContinue).Version
            if ($vcVersion) { $vcFound = $true; break }
        } catch {}
    }
}
if ($vcFound) {
    Write-Host "  VC++ 2022 x64   : " -NoNewline; Write-Host "[FOUND] $vcVersion" -ForegroundColor Green
} else {
    Write-Host "  VC++ 2022 x64   : " -NoNewline; Write-Host "[NOT FOUND] Required for PacketCircle to load" -ForegroundColor Red
    Write-Host "                    Install from: https://aka.ms/vs/17/release/vc_redist.x64.exe" -ForegroundColor Yellow
}

# --- Verify plugin binaries ---
Write-Host ""
Write-Host "  Plugin binaries in this installer:"
$v052Ok = $true
$v047Ok = $true
foreach ($ver in @("v.$LatestVersion", "v.$LegacyVersion")) {
    $path = Join-Path $ScriptDir "$ver\$PluginName"
    if (Test-Path $path) {
        $sz = [math]::Round((Get-Item $path).Length / 1KB)
        Write-Host "    $ver\$PluginName : " -NoNewline; Write-Host "[FOUND]  ($sz KB)" -ForegroundColor Green
    } else {
        Write-Host "    $ver\$PluginName : " -NoNewline; Write-Host "[MISSING]" -ForegroundColor Yellow
        if ($ver -eq "v.$LatestVersion") { $v052Ok = $false }
        if ($ver -eq "v.$LegacyVersion") { $v047Ok = $false }
    }
}
if (-not $v052Ok -and -not $v047Ok) {
    Write-Host ""
    Write-Host "  Error: No plugin binaries found in this installer package." -ForegroundColor Red
    Read-Host "  Press Enter to exit"; exit 1
}

# --- Detect Wireshark ---
Write-Host ""
Write-Host "  Searching for Wireshark:"
$WsVersion     = $null
$WiresharkPath = $null

foreach ($path in @(
    "$env:ProgramFiles\Wireshark",
    "${env:ProgramFiles(x86)}\Wireshark",
    "$env:LOCALAPPDATA\Programs\Wireshark"
)) {
    if (Test-Path "$path\Wireshark.exe") {
        Write-Host "    $path\Wireshark.exe : " -NoNewline; Write-Host "[FOUND]" -ForegroundColor Green
        $WiresharkPath = $path; break
    } else {
        Write-Host "    $path\Wireshark.exe : " -NoNewline; Write-Host "[not found]" -ForegroundColor DarkGray
    }
}

if ($WiresharkPath) {
    try {
        $vi = (Get-Item "$WiresharkPath\Wireshark.exe").VersionInfo
        $WsVersion = "$($vi.FileMajorPart).$($vi.FileMinorPart).$($vi.FileBuildPart)"
        Write-Host "    Version from EXE metadata: " -NoNewline; Write-Host $WsVersion -ForegroundColor Cyan
    } catch {}
}

if (-not $WsVersion) {
    $ts = Get-Command "tshark" -ErrorAction SilentlyContinue
    if ($ts) {
        try {
            $out = & tshark --version 2>&1 | Select-Object -First 1
            if ($out -match '(\d+\.\d+\.\d+)') { $WsVersion = $Matches[1] }
        } catch {}
    }
}

if (-not $WsVersion -and $WiresharkPath) {
    $tsharkExe = "$WiresharkPath\tshark.exe"
    if (Test-Path $tsharkExe) {
        try {
            $out = & $tsharkExe --version 2>&1 | Select-Object -First 1
            if ($out -match '(\d+\.\d+\.\d+)') { $WsVersion = $Matches[1] }
        } catch {}
    }
}

if (-not $WsVersion) {
    Write-Host ""
    Write-Host "  [WARN] Could not detect Wireshark version automatically." -ForegroundColor Yellow
    $inp = Read-Host "  Enter Wireshark major.minor version (e.g., 4.6)"
    $WsVersion = "$inp.0"
}

$WsMajor      = $WsVersion.Split('.')[0]
$WsMinor      = $WsVersion.Split('.')[1]
$PluginPathId = "$WsMajor.$WsMinor"

# --- Determine plugin directory ---
Write-Host ""
Write-Host "  Searching for plugin directory:"
$foundPathId = $null
$searchBases = @(
    $(if ($WiresharkPath) { "$WiresharkPath\plugins" } else { $null }),
    "$env:APPDATA\Wireshark\plugins",
    "$env:LOCALAPPDATA\Wireshark\plugins"
) | Where-Object { $_ }

foreach ($base in $searchBases) {
    if (Test-Path $base) {
        foreach ($d in (Get-ChildItem $base -Directory -ErrorAction SilentlyContinue)) {
            $match = $d.Name -match "^$WsMajor[\.\-]$WsMinor$"
            $color = if ($match) { "Green" } else { "DarkGray" }
            Write-Host "    $base\$($d.Name)  $(if ($match) {'[MATCH]'} else {''})" -ForegroundColor $color
            if ($match -and -not $foundPathId) { $foundPathId = $d.Name }
        }
    }
}

if ($foundPathId) {
    $PluginPathId = $foundPathId
    Write-Host "    => Using plugin path ID: " -NoNewline; Write-Host $PluginPathId -ForegroundColor Cyan
} else {
    Write-Host "    => No existing version directory found; will use default: " -NoNewline
    Write-Host $PluginPathId -ForegroundColor Yellow
}

$PersonalPluginDir = "$env:APPDATA\Wireshark\plugins\$PluginPathId\epan"
$SystemPluginDir   = if ($WiresharkPath) { "$WiresharkPath\plugins\$PluginPathId\epan" } else { $null }

# --- Detect currently installed version ---
Write-Host ""
Write-Host "  Checking for existing PacketCircle installation:"
$InstalledVersion = $null
$InstalledPath    = $null

foreach ($dir in (@($PersonalPluginDir, "$env:LOCALAPPDATA\Wireshark\plugins\$PluginPathId\epan", $SystemPluginDir) | Where-Object { $_ })) {
    $candidate = "$dir\$PluginName"
    if (Test-Path $candidate) {
        Write-Host "    $candidate : " -NoNewline; Write-Host "[FOUND]" -ForegroundColor Green
        $InstalledPath = $candidate
        try {
            $bytes = [System.IO.File]::ReadAllBytes($InstalledPath)
            $text  = [System.Text.Encoding]::ASCII.GetString($bytes)
            if ($text -match 'PacketCircle v\.(\d+\.\d+\.\d+)') {
                $InstalledVersion = $Matches[1]
                Write-Host "    Embedded version: " -NoNewline; Write-Host "v.$InstalledVersion" -ForegroundColor Cyan
            }
        } catch {}
        break
    } else {
        Write-Host "    $candidate : " -NoNewline; Write-Host "[not found]" -ForegroundColor DarkGray
    }
}
if (-not $InstalledPath) {
    Write-Host "    No existing installation found." -ForegroundColor DarkGray
}

# --- Summary ---
Write-Host ""
Write-Host "-----------------------------------------------------------" -ForegroundColor DarkGray
Write-Host "  Prerequisites Summary" -ForegroundColor White
Write-Host "-----------------------------------------------------------" -ForegroundColor DarkGray
Write-Host "  OS              : $osName  build $osBuild  $osArch"
Write-Host "  VC++ 2022 x64   : " -NoNewline
if ($vcFound) { Write-Host "OK ($vcVersion)" -ForegroundColor Green } else { Write-Host "NOT FOUND  (required)" -ForegroundColor Red }
Write-Host "  Wireshark       : " -NoNewline
if ($WiresharkPath) { Write-Host "Found at $WiresharkPath" -ForegroundColor Green } else { Write-Host "Not found in standard locations" -ForegroundColor Yellow }
Write-Host "  Wireshark ver   : " -NoNewline; Write-Host "$WsVersion  (plugin API: $PluginPathId)" -ForegroundColor Cyan
Write-Host "  v.0.5.2 binary  : " -NoNewline
if ($v052Ok) { Write-Host "present" -ForegroundColor Green } else { Write-Host "not available in this package" -ForegroundColor Yellow }
Write-Host "  v.0.4.7 binary  : " -NoNewline
if ($v047Ok) { Write-Host "present" -ForegroundColor Green } else { Write-Host "not available in this package" -ForegroundColor Yellow }
Write-Host "  Installed now   : " -NoNewline
if ($InstalledVersion) { Write-Host "v.$InstalledVersion  at $InstalledPath" -ForegroundColor Cyan } else { Write-Host "None" -ForegroundColor DarkGray }
Write-Host "-----------------------------------------------------------" -ForegroundColor DarkGray

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
    default { Write-Host "Invalid choice." -ForegroundColor Red; Read-Host "Press Enter to exit"; exit 1 }
}

# --- Version selection ---
Write-Host ""
Write-Host "Select version to install:"
Write-Host ""

if ($InstalledVersion -eq $LatestVersion) {
    Write-Host "  1) v.$LatestVersion (latest)   - already installed, reinstall"  -ForegroundColor Green
    Write-Host "  2) v.$LegacyVersion             - downgrade to stable legacy"    -ForegroundColor Yellow
} elseif ($InstalledVersion -eq $LegacyVersion) {
    Write-Host "  1) v.$LatestVersion (latest)   - upgrade (recommended)"          -ForegroundColor Green
    Write-Host "  2) v.$LegacyVersion             - already installed, reinstall"  -ForegroundColor Yellow
} else {
    Write-Host "  1) v.$LatestVersion (latest)   - 3-page PDF reports, graph view (opt-in), TCP Window analysis" -ForegroundColor Green
    Write-Host "  2) v.$LegacyVersion             - stable legacy: table view, protocol info dialogs, Wi-Fi mode" -ForegroundColor Yellow
}

Write-Host ""
$verChoice = Read-Host "Choice [1]"
if (-not $verChoice) { $verChoice = "1" }

$SelectedVersion = $null
switch ($verChoice) {
    "1" {
        if (-not $v052Ok) {
            Write-Host "v.$LatestVersion binary is not available in this installer." -ForegroundColor Red
            Read-Host "Press Enter to exit"; exit 1
        }
        $SelectedVersion = $LatestVersion
    }
    "2" {
        if (-not $v047Ok) {
            Write-Host "v.$LegacyVersion binary is not available in this installer." -ForegroundColor Red
            Read-Host "Press Enter to exit"; exit 1
        }
        $SelectedVersion = $LegacyVersion
        if ($InstalledVersion -ne $LegacyVersion) {
            Write-Host ""
            Write-Host "  You chose v.$LegacyVersion (legacy release)." -ForegroundColor Yellow
            $confirm = Read-Host "  Continue with v.$LegacyVersion? [y/N]"
            if ($confirm -ne "y" -and $confirm -ne "Y") { Write-Host "Installation cancelled."; Read-Host "Press Enter to exit"; exit 0 }
        }
    }
    default { Write-Host "Invalid choice." -ForegroundColor Red; Read-Host "Press Enter to exit"; exit 1 }
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

# --- Feature set selection (v.0.5.2 only) ---
$EnableExperimental = $false
if ($SelectedVersion -eq $LatestVersion) {
    Write-Host ""
    Write-Host "Feature set:"
    Write-Host ""
    Write-Host "  1) Standard (recommended)" -ForegroundColor Green
    Write-Host "     Circle view, Table view, Wi-Fi mode, 20+ protocol info dialogs,"
    Write-Host "     PDF reports, ntopng/Malcolm integration - stable, fully tested"
    Write-Host ""
    Write-Host "  2) Experimental - enables Graph View (beta)" -ForegroundColor Cyan
    Write-Host "     Everything in Standard, plus an interactive node-link topology"
    Write-Host "     diagram with 8 layouts, TCP Health / Anomaly Score / High Risk"
    Write-Host "     edge colors, and score breakdowns. Beta quality - may have rough edges."
    Write-Host ""
    $featChoice = Read-Host "Choice [1]"
    if (-not $featChoice) { $featChoice = "1" }
    switch ($featChoice) {
        "2" { $EnableExperimental = $true }
        "1" { $EnableExperimental = $false }
        default { Write-Host "Invalid choice." -ForegroundColor Red; Read-Host "Press Enter to exit"; exit 1 }
    }
}

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

# --- Install binary ---
Write-Host ""
Write-Host "Installing to: $InstallDir" -ForegroundColor Cyan
if (-not (Test-Path $InstallDir)) { New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null }
Copy-Item $PluginFile "$InstallDir\$PluginName" -Force
try { Unblock-File "$InstallDir\$PluginName" -ErrorAction SilentlyContinue } catch {}

# --- Write experimental settings if requested ---
$SettingsFile = "$env:USERPROFILE\.PacketCircle\settings.ini"
if ($EnableExperimental) {
    $settingsDir = Split-Path $SettingsFile
    if (-not (Test-Path $settingsDir)) { New-Item -ItemType Directory -Force -Path $settingsDir | Out-Null }

    # Read existing file, strip old [Beta] section, re-append
    $existing = @()
    if (Test-Path $SettingsFile) {
        $inBeta = $false
        foreach ($line in (Get-Content $SettingsFile)) {
            if ($line -match '^\[Beta\]') { $inBeta = $true; continue }
            if ($inBeta -and $line -match '^\[') { $inBeta = $false }
            if (-not $inBeta) { $existing += $line }
        }
    }
    $existing += ""
    $existing += "[Beta]"
    $existing += "EnableGraphView=true"
    Set-Content -Path $SettingsFile -Value $existing -Encoding UTF8
    Write-Host "[OK] Experimental Graph View enabled in $SettingsFile" -ForegroundColor Cyan
}

# --- Verify ---
if (Test-Path "$InstallDir\$PluginName") {
    Write-Host ""
    Write-Host "===========================================================" -ForegroundColor Green
    Write-Host "      Installation successful!" -ForegroundColor Green
    Write-Host "===========================================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Installed:  PacketCircle v.$SelectedVersion" -ForegroundColor Cyan -NoNewline
    if ($EnableExperimental) { Write-Host "  [Experimental - Graph View enabled]" -ForegroundColor Cyan } else { Write-Host "" }
    Write-Host "  Location:   $InstallDir\$PluginName"
    Write-Host ""
    Write-Host "  Next steps:"
    Write-Host "  1. Restart Wireshark (if running)"
    Write-Host "  2. Open a capture or start a live capture"
    Write-Host "  3. Look for PacketCircle in the Tools menu"
    if ($EnableExperimental) {
        Write-Host "  4. The Graph button appears in the PacketCircle toolbar"
    }
    Write-Host ""

    if (-not $vcFound) {
        Write-Host "  [WARN] VC++ 2022 Redistributable (x64) was not detected." -ForegroundColor Red
        Write-Host "         If PacketCircle fails to load, install it from:"    -ForegroundColor Yellow
        Write-Host "         https://aka.ms/vs/17/release/vc_redist.x64.exe"     -ForegroundColor Yellow
        Write-Host ""
    }

    Write-Host "  To uninstall, run this script again and choose 'u'."
    if ($EnableExperimental) {
        Write-Host ""
        Write-Host "  [NOTE] Graph View (Experimental) - QA on Windows has been basic only." -ForegroundColor Yellow
        Write-Host "         If you encounter issues, run the installer again and choose" -ForegroundColor Yellow
        Write-Host "         Standard to disable it (removes EnableGraphView from settings.ini)." -ForegroundColor Yellow
    }
    Write-Host ""
} else {
    Write-Host "Error: Installation failed." -ForegroundColor Red
    Read-Host "Press Enter to exit"; exit 1
}

Read-Host "Press Enter to exit"
