# =============================================================================
# PacketCircle Windows Troubleshooting Script (PowerShell)
# =============================================================================
#
# Diagnoses DLL dependency and installation issues for the PacketCircle
# Wireshark plugin on Windows 10/11.
#
# What it checks:
#   1. System information and environment (including WoW64 detection)
#   2. Plugin DLL analysis (PE header, architecture, linker version)
#   3. Wireshark installation, version, and architecture
#   4. Plugin directory paths (personal + system)
#   5. VC++ Redistributable version and CRT DLLs
#   6. DLL dependency resolution (all imported DLLs)
#   7. Import symbol verification (every imported function)
#   8. DLL load test (three-stage)
#   9. Wireshark plugin loading check (tshark -G plugins)
#  10. Security checks (Zone.Identifier, antivirus, config)
#
# Usage:
#   .\troubleshoot.ps1
#   .\troubleshoot.ps1 -DllPath "C:\path\to\packetcircle.dll"
#   .\troubleshoot.ps1 | Tee-Object -FilePath report.txt
#
# Requirements:
#   - PowerShell 5.1+ (built into Windows 10/11)
#   - Windows 10/11 x86_64
#
# Copyright (C) 2026 Walter Hofstetter
# License: GPL v2+
# AI-Assisted: yes (Claude)
# =============================================================================

param(
    [string]$DllPath = ""
)

$ErrorActionPreference = "Continue"

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
$PLUGIN_NAME = "packetcircle.dll"
$IMAGE_FILE_MACHINE_AMD64 = 0x8664
$IMAGE_FILE_MACHINE_I386  = 0x14C
$IMAGE_FILE_MACHINE_ARM64 = 0xAA64

# DLLs that Wireshark bundles - only found in Wireshark's install directory
$WIRESHARK_PROVIDED_DLLS = @(
    "libwireshark.dll", "libwiretap.dll", "libwsutil.dll",
    "Qt6Core.dll", "Qt6Gui.dll", "Qt6Widgets.dll",
    "glib-2.0-0.dll"
)

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
function Write-OK     { param([string]$Msg) Write-Host "  [OK]   " -ForegroundColor Green -NoNewline; Write-Host $Msg }
function Write-Warn   { param([string]$Msg) Write-Host "  [WARN] " -ForegroundColor Yellow -NoNewline; Write-Host $Msg }
function Write-Fail   { param([string]$Msg) Write-Host "  [FAIL] " -ForegroundColor Red -NoNewline; Write-Host $Msg }
function Write-Info   { param([string]$Msg) Write-Host "  [INFO] " -ForegroundColor Cyan -NoNewline; Write-Host $Msg }

function Write-Section {
    param([string]$Title)
    Write-Host ""
    Write-Host ("=" * 64) -ForegroundColor White
    Write-Host "  $Title" -ForegroundColor White
    Write-Host ("=" * 64) -ForegroundColor White
}

# Counters
$script:IssuesFound = 0
$script:WarningsFound = 0

# ---------------------------------------------------------------------------
# WoW64 detection - 32-bit PowerShell on 64-bit Windows
# ---------------------------------------------------------------------------
$script:IsWoW64 = $false
$script:NativeSystem32 = Join-Path $env:SystemRoot "System32"
$script:NativeProgramFiles = $env:ProgramFiles

if ([IntPtr]::Size -eq 4 -and $env:PROCESSOR_ARCHITEW6432) {
    # 32-bit process on 64-bit OS
    $script:IsWoW64 = $true
    # Sysnative gives a 32-bit process access to the real 64-bit System32
    $script:NativeSystem32 = Join-Path $env:SystemRoot "Sysnative"
    # ProgramW6432 points to 64-bit Program Files
    if ($env:ProgramW6432) {
        $script:NativeProgramFiles = $env:ProgramW6432
    }
}

# ---------------------------------------------------------------------------
# PE Parser - reads PE header, section table, and import directory
# ---------------------------------------------------------------------------
function Read-PEHeader {
    param([string]$FilePath)

    $result = [PSCustomObject]@{
        Valid            = $false
        Machine          = 0
        MachineName      = "Unknown"
        Is64Bit          = $false
        LinkerMajor      = 0
        LinkerMinor      = 0
        OSMajor          = 0
        OSMinor          = 0
        SubsystemMajor   = 0
        SubsystemMinor   = 0
        Subsystem        = 0
        Timestamp        = 0
        TimestampDate    = $null
        NumSections      = 0
        Sections         = @()
        Imports          = @()
        ErrorMessage     = ""
    }

    try {
        $bytes = [System.IO.File]::ReadAllBytes($FilePath)

        # DOS header
        if ($bytes[0] -ne 0x4D -or $bytes[1] -ne 0x5A) {
            $result.ErrorMessage = "Not a valid PE file (missing MZ signature)"
            return $result
        }

        $peOffset = [BitConverter]::ToUInt32($bytes, 0x3C)

        # PE signature
        if ($bytes[$peOffset] -ne 0x50 -or $bytes[$peOffset+1] -ne 0x45 -or
            $bytes[$peOffset+2] -ne 0x00 -or $bytes[$peOffset+3] -ne 0x00) {
            $result.ErrorMessage = "Not a valid PE file (missing PE signature)"
            return $result
        }

        # COFF header
        $coff = $peOffset + 4
        $result.Machine     = [BitConverter]::ToUInt16($bytes, $coff)
        $result.NumSections = [BitConverter]::ToUInt16($bytes, $coff + 2)
        $result.Timestamp   = [BitConverter]::ToUInt32($bytes, $coff + 4)
        $optHeaderSize      = [BitConverter]::ToUInt16($bytes, $coff + 16)

        try {
            $epoch = [DateTime]::new(1970, 1, 1, 0, 0, 0, [DateTimeKind]::Utc)
            $result.TimestampDate = $epoch.AddSeconds($result.Timestamp).ToLocalTime()
        } catch {}

        switch ($result.Machine) {
            $IMAGE_FILE_MACHINE_AMD64 { $result.MachineName = "x86_64 (AMD64)" }
            $IMAGE_FILE_MACHINE_I386  { $result.MachineName = "x86 (i386)" }
            $IMAGE_FILE_MACHINE_ARM64 { $result.MachineName = "ARM64" }
            default                   { $result.MachineName = "Unknown (0x{0:X})" -f $result.Machine }
        }

        # Optional header
        $opt = $coff + 20
        $magic = [BitConverter]::ToUInt16($bytes, $opt)
        $result.Is64Bit = ($magic -eq 0x020B)

        $result.LinkerMajor    = $bytes[$opt + 2]
        $result.LinkerMinor    = $bytes[$opt + 3]
        $result.OSMajor        = [BitConverter]::ToUInt16($bytes, $opt + 40)
        $result.OSMinor        = [BitConverter]::ToUInt16($bytes, $opt + 42)
        $result.SubsystemMajor = [BitConverter]::ToUInt16($bytes, $opt + 48)
        $result.SubsystemMinor = [BitConverter]::ToUInt16($bytes, $opt + 50)

        if ($result.Is64Bit) {
            $result.Subsystem = [BitConverter]::ToUInt16($bytes, $opt + 68)
            $numRvaSizes   = [BitConverter]::ToUInt32($bytes, $opt + 108)
            $dataDirOffset = $opt + 112
        } else {
            $result.Subsystem = [BitConverter]::ToUInt16($bytes, $opt + 68)
            $numRvaSizes   = [BitConverter]::ToUInt32($bytes, $opt + 92)
            $dataDirOffset = $opt + 96
        }

        # Section headers
        $sectionOffset = $opt + $optHeaderSize
        $sections = @()
        for ($i = 0; $i -lt $result.NumSections; $i++) {
            $s = $sectionOffset + $i * 40
            $nameBytes = $bytes[$s..($s + 7)]
            $nameStr = [System.Text.Encoding]::ASCII.GetString($nameBytes).TrimEnd("`0")
            $vSize = [BitConverter]::ToUInt32($bytes, $s + 8)
            $vAddr = [BitConverter]::ToUInt32($bytes, $s + 12)
            $rSize = [BitConverter]::ToUInt32($bytes, $s + 16)
            $rOff  = [BitConverter]::ToUInt32($bytes, $s + 20)
            $sections += [PSCustomObject]@{
                Name         = $nameStr
                VirtualSize  = $vSize
                VirtualAddr  = $vAddr
                RawSize      = $rSize
                RawOffset    = $rOff
            }
        }
        $result.Sections = $sections

        # Import directory (data directory index 1)
        if ($numRvaSizes -gt 1) {
            $importRva  = [BitConverter]::ToUInt32($bytes, $dataDirOffset + 8)
            $importSize = [BitConverter]::ToUInt32($bytes, $dataDirOffset + 12)

            if ($importRva -gt 0 -and $importSize -gt 0) {
                $result.Imports = Read-PEImports -Bytes $bytes -ImportRva $importRva -Sections $sections -Is64Bit $result.Is64Bit
            }
        }

        $result.Valid = $true
    }
    catch {
        $result.ErrorMessage = $_.Exception.Message
    }

    return $result
}

function Convert-RvaToOffset {
    param(
        [uint32]$Rva,
        [array]$Sections
    )
    foreach ($sec in $Sections) {
        $maxSize = [Math]::Max($sec.VirtualSize, $sec.RawSize)
        if ($Rva -ge $sec.VirtualAddr -and $Rva -lt ($sec.VirtualAddr + $maxSize)) {
            return $sec.RawOffset + ($Rva - $sec.VirtualAddr)
        }
    }
    return -1
}

function Read-PEImports {
    param(
        [byte[]]$Bytes,
        [uint32]$ImportRva,
        [array]$Sections,
        [bool]$Is64Bit
    )

    $imports = @()
    $offset = Convert-RvaToOffset -Rva $ImportRva -Sections $Sections
    if ($offset -lt 0) { return $imports }

    while ($true) {
        if (($offset + 20) -gt $Bytes.Length) { break }

        $iltRva  = [BitConverter]::ToUInt32($Bytes, $offset)
        $nameRva = [BitConverter]::ToUInt32($Bytes, $offset + 12)

        if ($nameRva -eq 0) { break }

        $nameOff = Convert-RvaToOffset -Rva $nameRva -Sections $Sections
        if ($nameOff -lt 0) { $offset += 20; continue }

        # Read null-terminated DLL name
        $endIdx = $nameOff
        while ($endIdx -lt $Bytes.Length -and $Bytes[$endIdx] -ne 0) { $endIdx++ }
        $dllName = [System.Text.Encoding]::ASCII.GetString($Bytes, $nameOff, $endIdx - $nameOff)

        # Parse imported functions
        $functions = @()
        if ($iltRva -gt 0) {
            $iltOff = Convert-RvaToOffset -Rva $iltRva -Sections $Sections
            if ($iltOff -ge 0) {
                $entrySize = if ($Is64Bit) { 8 } else { 4 }
                $ordinalFlag = if ($Is64Bit) { [uint64]1 -shl 63 } else { [uint32]1 -shl 31 }
                $pos = $iltOff

                while (($pos + $entrySize) -le $Bytes.Length) {
                    if ($Is64Bit) {
                        $val = [BitConverter]::ToUInt64($Bytes, $pos)
                    } else {
                        $val = [BitConverter]::ToUInt32($Bytes, $pos)
                    }
                    if ($val -eq 0) { break }

                    if ($val -band $ordinalFlag) {
                        $functions += [PSCustomObject]@{ Ordinal = ($val -band 0xFFFF); Name = $null }
                    } else {
                        $hintRva = [uint32]($val -band 0x7FFFFFFF)
                        $hintOff = Convert-RvaToOffset -Rva $hintRva -Sections $Sections
                        if ($hintOff -ge 0 -and ($hintOff + 2) -lt $Bytes.Length) {
                            $fnEnd = $hintOff + 2
                            while ($fnEnd -lt $Bytes.Length -and $Bytes[$fnEnd] -ne 0) { $fnEnd++ }
                            $fnName = [System.Text.Encoding]::ASCII.GetString($Bytes, $hintOff + 2, $fnEnd - ($hintOff + 2))
                            $functions += [PSCustomObject]@{ Ordinal = $null; Name = $fnName }
                        }
                    }
                    $pos += $entrySize
                }
            }
        }

        $imports += [PSCustomObject]@{
            DllName   = $dllName
            Functions = $functions
        }
        $offset += 20
    }

    return $imports
}

# ---------------------------------------------------------------------------
# Wireshark detection helpers
# ---------------------------------------------------------------------------
function Find-Wireshark {
    # Build search list - include native 64-bit paths even from 32-bit PowerShell
    $searchPaths = @(
        "$env:ProgramFiles\Wireshark"
    )
    # On WoW64, ProgramFiles points to Program Files (x86). Add real 64-bit path.
    if ($script:NativeProgramFiles -ne $env:ProgramFiles) {
        $searchPaths = @("$($script:NativeProgramFiles)\Wireshark") + $searchPaths
    }
    $searchPaths += @(
        "${env:ProgramFiles(x86)}\Wireshark",
        "$env:LOCALAPPDATA\Programs\Wireshark"
    )

    foreach ($p in $searchPaths) {
        if ($p -and (Test-Path "$p\Wireshark.exe")) { return $p }
    }
    # Try PATH
    $ws = Get-Command "Wireshark.exe" -ErrorAction SilentlyContinue
    if ($ws) { return Split-Path $ws.Source }
    return $null
}

function Get-WiresharkVersion {
    param([string]$WsPath)

    foreach ($exe in @("tshark.exe", "Wireshark.exe")) {
        $exePath = Join-Path $WsPath $exe
        if (Test-Path $exePath) {
            try {
                $output = & $exePath --version 2>&1 | Select-Object -First 3
                foreach ($line in $output) {
                    if ($line -match '(\d+\.\d+\.\d+)') {
                        return $Matches[1]
                    }
                }
            } catch {}
        }
    }
    return $null
}

function Get-WiresharkArchitecture {
    param([string]$WsPath)
    $exePath = Join-Path $WsPath "Wireshark.exe"
    if (Test-Path $exePath) {
        try {
            $pe = Read-PEHeader -FilePath $exePath
            if ($pe.Valid) { return $pe }
        } catch {}
    }
    return $null
}

# ---------------------------------------------------------------------------
# DLL resolution helpers
# ---------------------------------------------------------------------------
function Find-DllInSearchPath {
    param(
        [string]$DllName,
        [string]$WiresharkPath
    )

    $dllLower = $DllName.ToLower()

    # API set DLLs - virtual, always resolved by the loader
    if ($dllLower.StartsWith("api-ms-win-") -or $dllLower.StartsWith("ext-ms-win-")) {
        return [PSCustomObject]@{ Path = "(API set - resolved by Windows loader)"; Method = "api-set" }
    }

    # Wireshark directory (application directory in plugin context)
    if ($WiresharkPath) {
        $candidate = Join-Path $WiresharkPath $DllName
        if (Test-Path $candidate) {
            return [PSCustomObject]@{ Path = $candidate; Method = "wireshark-dir" }
        }
    }

    # Native 64-bit System32 (use Sysnative when in WoW64)
    $candidate = Join-Path $script:NativeSystem32 $DllName
    if (Test-Path $candidate) {
        return [PSCustomObject]@{ Path = $candidate; Method = "system32" }
    }

    # Also check the process-visible System32 if different
    $sys32 = Join-Path $env:SystemRoot "System32"
    if ($sys32 -ne $script:NativeSystem32) {
        $candidate = Join-Path $sys32 $DllName
        if (Test-Path $candidate) {
            return [PSCustomObject]@{ Path = $candidate; Method = "system32-wow" }
        }
    }

    # Windows directory
    $candidate = Join-Path $env:SystemRoot $DllName
    if (Test-Path $candidate) {
        return [PSCustomObject]@{ Path = $candidate; Method = "windows-dir" }
    }

    # PATH
    foreach ($dir in ($env:PATH -split ";")) {
        $dir = $dir.Trim()
        if ($dir -and (Test-Path $dir)) {
            $candidate = Join-Path $dir $DllName
            if (Test-Path $candidate) {
                return [PSCustomObject]@{ Path = $candidate; Method = "PATH" }
            }
        }
    }

    return $null
}

function Get-DllFileVersion {
    param([string]$FilePath)
    try {
        $vi = (Get-Item $FilePath).VersionInfo
        if ($vi.FileVersion) { return $vi.FileVersion }
        return "$($vi.FileMajorPart).$($vi.FileMinorPart).$($vi.FileBuildPart).$($vi.FilePrivatePart)"
    } catch {
        return $null
    }
}

# ---------------------------------------------------------------------------
# DLL load test via P/Invoke
# ---------------------------------------------------------------------------
$LoadLibrarySignatures = @"
using System;
using System.Runtime.InteropServices;

public class NativeMethods {
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern IntPtr LoadLibraryExW(string lpLibFileName, IntPtr hFile, uint dwFlags);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool FreeLibrary(IntPtr hModule);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool SetDllDirectoryW(string lpPathName);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    public const uint LOAD_LIBRARY_AS_DATAFILE = 0x00000002;
    public const uint DONT_RESOLVE_DLL_REFERENCES = 0x00000001;
    public const uint LOAD_LIBRARY_AS_IMAGE_RESOURCE = 0x00000020;
}
"@

try {
    Add-Type -TypeDefinition $LoadLibrarySignatures -ErrorAction SilentlyContinue
} catch {
    # Type may already be added in this session
}

function Test-DllLoad {
    param(
        [string]$DllPath,
        [uint32]$Flags
    )
    $handle = [NativeMethods]::LoadLibraryExW($DllPath, [IntPtr]::Zero, $Flags)
    if ($handle -ne [IntPtr]::Zero) {
        [NativeMethods]::FreeLibrary($handle) | Out-Null
        return [PSCustomObject]@{ Success = $true; ErrorCode = 0; Message = "OK" }
    }
    $errCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
    $errMsg = (New-Object System.ComponentModel.Win32Exception($errCode)).Message
    return [PSCustomObject]@{ Success = $false; ErrorCode = $errCode; Message = $errMsg }
}

function Test-DllLoadWithContext {
    param(
        [string]$DllPath,
        [string]$WiresharkPath
    )
    [NativeMethods]::SetDllDirectoryW($WiresharkPath) | Out-Null
    $result = Test-DllLoad -DllPath $DllPath -Flags 0
    [NativeMethods]::SetDllDirectoryW($null) | Out-Null
    return $result
}

function Test-FunctionInDll {
    param(
        [string]$DllPath,
        [string]$FunctionName
    )
    $handle = [NativeMethods]::LoadLibraryExW($DllPath, [IntPtr]::Zero, [NativeMethods]::DONT_RESOLVE_DLL_REFERENCES)
    if ($handle -eq [IntPtr]::Zero) { return $null }
    try {
        $addr = [NativeMethods]::GetProcAddress($handle, $FunctionName)
        return ($addr -ne [IntPtr]::Zero)
    } finally {
        [NativeMethods]::FreeLibrary($handle) | Out-Null
    }
}


# ===========================================================================
# MAIN
# ===========================================================================

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "   PacketCircle Windows Troubleshooting Tool (PowerShell)       " -ForegroundColor Cyan
Write-Host "   Dependency & Installation Diagnostics                        " -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan

# --- Resolve plugin DLL path ---
if (-not $DllPath) {
    $scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
    $candidates = @(
        (Join-Path $scriptDir $PLUGIN_NAME),
        (Join-Path $scriptDir "..\installer\windows-x86_64\$PLUGIN_NAME"),
        "$env:APPDATA\Wireshark\plugins\4-6\epan\$PLUGIN_NAME",
        "$env:APPDATA\Wireshark\plugins\4.6\epan\$PLUGIN_NAME"
    )
    foreach ($c in $candidates) {
        if (Test-Path $c) { $DllPath = $c; break }
    }
    if (-not $DllPath) { $DllPath = Join-Path $scriptDir $PLUGIN_NAME }
}
$DllPath = [System.IO.Path]::GetFullPath($DllPath)

# =====================================================================
# Section 1: System Information
# =====================================================================
Write-Section "1. System Information"

Write-Info "PowerShell: $($PSVersionTable.PSVersion)"
$processBits = [IntPtr]::Size * 8
Write-Info "Architecture: ${processBits}-bit process"

try {
    $os = Get-CimInstance Win32_OperatingSystem
    Write-Info "OS: $($os.Caption) ($($os.Version)) Build $($os.BuildNumber)"
} catch {
    try {
        $ver = [Environment]::OSVersion.Version
        Write-Info "OS: Windows $($ver.Major).$($ver.Minor) Build $($ver.Build)"
    } catch {
        Write-Warn "Could not determine OS version"
    }
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Info "Running as admin: $(if ($isAdmin) { 'Yes' } else { 'No' })"

# WoW64 warning
if ($script:IsWoW64) {
    Write-Warn "Running 32-bit PowerShell on 64-bit Windows (WoW64)"
    Write-Warn "Some checks are adapted; for best results use 64-bit PowerShell:"
    Write-Warn "  C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe .\troubleshoot.ps1"
} else {
    if ($processBits -eq 64) {
        Write-OK "Running native 64-bit PowerShell"
    }
}

# =====================================================================
# Section 2: Plugin DLL Analysis
# =====================================================================
Write-Section "2. Plugin DLL Analysis"

$pe = $null
if (-not (Test-Path $DllPath)) {
    Write-Fail "Plugin DLL not found: $DllPath"
    Write-Host ""
    Write-Host '  Specify the path:  .\troubleshoot.ps1 -DllPath "C:\path\to\packetcircle.dll"'
    $script:IssuesFound++
} else {
    $fileInfo = Get-Item $DllPath
    Write-OK "Found: $DllPath"
    Write-Info "Size: $($fileInfo.Length.ToString('N0')) bytes ($([math]::Round($fileInfo.Length / 1KB, 1)) KB)"
    Write-Info "Last modified: $($fileInfo.LastWriteTime)"

    $pe = Read-PEHeader -FilePath $DllPath
    if ($pe.Valid) {
        Write-OK "Valid PE file"
        Write-Info "Architecture: $($pe.MachineName)"
        Write-Info "64-bit: $($pe.Is64Bit)"
        Write-Info "Linker: MSVC $($pe.LinkerMajor).$($pe.LinkerMinor)"
        Write-Info "Min OS version: $($pe.OSMajor).$($pe.OSMinor)"
        Write-Info "Subsystem version: $($pe.SubsystemMajor).$($pe.SubsystemMinor)"
        Write-Info "Sections: $($pe.NumSections)"
        Write-Info "Imported DLLs: $($pe.Imports.Count)"
        if ($pe.TimestampDate) {
            Write-Info "Build timestamp: $($pe.TimestampDate)"
        }

        if ($pe.Machine -ne $IMAGE_FILE_MACHINE_AMD64) {
            Write-Fail "Plugin is NOT x86_64! It is $($pe.MachineName)"
            Write-Fail "Wireshark 64-bit requires an x86_64 plugin"
            $script:IssuesFound++
        }

        if ($pe.SubsystemMajor -le 10) {
            Write-OK "OS version requirement ($($pe.OSMajor).$($pe.OSMinor)) is compatible with Windows 10"
        } else {
            Write-Fail "Plugin requires Windows $($pe.SubsystemMajor).$($pe.SubsystemMinor)+ -- may be incompatible"
            $script:IssuesFound++
        }
    } else {
        Write-Fail "Failed to parse PE: $($pe.ErrorMessage)"
        $script:IssuesFound++
    }
}

# =====================================================================
# Section 3: Wireshark Installation
# =====================================================================
Write-Section "3. Wireshark Installation"

$wsPath = Find-Wireshark
$wsVersion = $null

if (-not $wsPath) {
    Write-Warn "Wireshark installation not found in standard locations"
    if ($script:IsWoW64) {
        Write-Info "Note: 32-bit PowerShell may not see 64-bit Program Files"
        Write-Info "Checked: $($script:NativeProgramFiles)\Wireshark, $env:ProgramFiles\Wireshark, PATH"
    } else {
        Write-Info "Checked: Program Files, Program Files (x86), LocalAppData, PATH"
    }
    Write-Info "Wireshark-provided DLLs cannot be verified without the install path"
    $script:WarningsFound++
} else {
    Write-OK "Wireshark found: $wsPath"

    $wsPe = Get-WiresharkArchitecture -WsPath $wsPath
    if ($wsPe -and $wsPe.Valid) {
        Write-Info "Wireshark architecture: $($wsPe.MachineName)"
        if ($pe -and $pe.Valid -and $pe.Machine -ne $wsPe.Machine) {
            Write-Fail "ARCHITECTURE MISMATCH!"
            Write-Fail "  Plugin:    $($pe.MachineName)"
            Write-Fail "  Wireshark: $($wsPe.MachineName)"
            $script:IssuesFound++
        } elseif ($pe -and $pe.Valid) {
            Write-OK "Architecture match: both $($pe.MachineName)"
        }
    }

    $wsVersion = Get-WiresharkVersion -WsPath $wsPath
    if ($wsVersion) {
        Write-OK "Wireshark version: $wsVersion"
        $parts = $wsVersion.Split(".")
        if ($parts.Count -ge 2) {
            $wsMajor = [int]$parts[0]
            $wsMinor = [int]$parts[1]
            if ($wsMajor -eq 4 -and $wsMinor -eq 6) {
                Write-OK "Version 4.6.x confirmed - compatible with plugin"
            } else {
                Write-Fail "Version $wsVersion may be incompatible with this plugin (built for 4.6.x)"
                $script:IssuesFound++
            }
        }
    } else {
        Write-Warn "Could not determine Wireshark version"
        $script:WarningsFound++
    }

    # Show bundled DLLs the plugin needs
    if ($pe -and $pe.Valid) {
        Write-Info "Wireshark-bundled DLLs used by plugin:"
        foreach ($imp in $pe.Imports) {
            $wsDll = Join-Path $wsPath $imp.DllName
            if (Test-Path $wsDll) {
                $ver = Get-DllFileVersion -FilePath $wsDll
                $verStr = if ($ver) { " (v$ver)" } else { "" }
                Write-Info "  $($imp.DllName)$verStr"
            }
        }
    }
}

# =====================================================================
# Section 4: Plugin Directory Check
# =====================================================================
Write-Section "4. Plugin Directory Check"

# Scan existing personal plugin directories
$personalBase = "$env:APPDATA\Wireshark\plugins"
if (Test-Path $personalBase) {
    Write-Info "Existing personal plugin directories:"
    Get-ChildItem $personalBase -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $epanDir = Join-Path $_.FullName "epan"
        $hasPlugin = Test-Path (Join-Path $epanDir $PLUGIN_NAME)
        $status = if ($hasPlugin) { " <-- $PLUGIN_NAME INSTALLED" } else { "" }
        if ($hasPlugin) {
            Write-OK "  $($_.Name)/epan/$status"
        } else {
            Write-Info "  $($_.Name)/"
        }
    }
} else {
    Write-Warn "Personal plugin base not found: $personalBase"
    $script:WarningsFound++
}

# Expected directories
if ($wsVersion) {
    $parts = $wsVersion.Split(".")
    if ($parts.Count -ge 2) {
        $dashId = "$($parts[0])-$($parts[1])"
        $dotId  = "$($parts[0]).$($parts[1])"

        Write-Info "Expected plugin paths for Wireshark $wsVersion :"
        foreach ($pair in @(
            @("Personal (dashes)", "$env:APPDATA\Wireshark\plugins\$dashId\epan"),
            @("Personal (dots)",   "$env:APPDATA\Wireshark\plugins\$dotId\epan")
        )) {
            $label = $pair[0]; $path = $pair[1]
            $hasPlugin = Test-Path (Join-Path $path $PLUGIN_NAME)
            if ($hasPlugin) {
                Write-OK "  [$label] $path -> $PLUGIN_NAME INSTALLED"
            } elseif (Test-Path $path) {
                Write-Warn "  [$label] $path -> directory exists but NO plugin"
                $script:WarningsFound++
            } else {
                Write-Info "  [$label] $path -> does not exist"
            }
        }
    }
}

# System plugin directories
if ($wsPath) {
    $sysPluginBase = Join-Path $wsPath "plugins"
    if (Test-Path $sysPluginBase) {
        Write-Info "System plugin directories:"
        Get-ChildItem $sysPluginBase -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            Write-Info "  $($_.Name)/"
            $epanDir = Join-Path $_.FullName "epan"
            if (Test-Path $epanDir) {
                Get-ChildItem $epanDir -File -ErrorAction SilentlyContinue | ForEach-Object {
                    Write-Info "    epan/$($_.Name)"
                }
            }
        }
    }
}

# =====================================================================
# Section 5: VC++ Runtime Check
# =====================================================================
Write-Section "5. Visual C++ Runtime Check"

$vcKeys = @(
    "HKLM:\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\X64",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\VisualStudio\14.0\VC\Runtimes\X64"
)
$vcFound = $false
foreach ($key in $vcKeys) {
    try {
        $reg = Get-ItemProperty $key -ErrorAction Stop
        Write-OK "VC++ Redistributable (x64): $($reg.Version) (Major=$($reg.Major), Minor=$($reg.Minor), Build=$($reg.Bld))"
        $vcFound = $true
        if ($reg.Minor -lt 40) {
            Write-Warn "VC++ runtime minor version $($reg.Minor) may be too old for MSVC 14.44 plugin"
            Write-Warn "Recommend: https://aka.ms/vs/17/release/vc_redist.x64.exe"
            $script:WarningsFound++
        } else {
            Write-OK "VC++ runtime version is compatible with MSVC 14.44 linker"
        }
        break
    } catch {}
}
if (-not $vcFound) {
    Write-Fail "VC++ 2015-2022 Redistributable (x64) NOT FOUND in registry!"
    Write-Fail "Install from: https://aka.ms/vs/17/release/vc_redist.x64.exe"
    $script:IssuesFound++
}

# CRT DLLs - check the native 64-bit System32, not the WoW64 redirected one
$crtCheckDir = $script:NativeSystem32
if ($script:IsWoW64) {
    Write-Info "CRT DLL versions in native System32 (via Sysnative):"
} else {
    Write-Info "CRT DLL versions in System32:"
}
foreach ($dllName in @("VCRUNTIME140.dll", "VCRUNTIME140_1.dll", "MSVCP140.dll", "ucrtbase.dll")) {
    $dllPath = Join-Path $crtCheckDir $dllName
    if (Test-Path $dllPath) {
        $ver = Get-DllFileVersion -FilePath $dllPath
        if ($ver) { Write-OK "  ${dllName}: v$ver" } else { Write-OK "  ${dllName}: present" }
    } else {
        # For CRT DLLs: missing in native System32 is a real issue
        Write-Fail "  ${dllName}: MISSING in $crtCheckDir"
        $script:IssuesFound++
    }
}

if ($wsPath) {
    Write-Info "CRT DLLs in Wireshark directory:"
    foreach ($dllName in @("VCRUNTIME140.dll", "VCRUNTIME140_1.dll", "MSVCP140.dll", "ucrtbase.dll")) {
        $dllPath = Join-Path $wsPath $dllName
        if (Test-Path $dllPath) {
            $ver = Get-DllFileVersion -FilePath $dllPath
            if ($ver) { Write-Info "  ${dllName}: v$ver" } else { Write-Info "  ${dllName}: present" }
        }
    }
}

# =====================================================================
# Section 6: DLL Dependency Resolution
# =====================================================================
Write-Section "6. DLL Dependency Resolution"

if ($pe -and $pe.Valid -and (Test-Path $DllPath)) {
    $totalImports = $pe.Imports.Count
    $resolved = 0
    $failedDeps = @()
    $wsProvidedNotFound = @()

    # Can we verify functions? Not reliably in WoW64 (32-bit can't load 64-bit DLLs)
    $canVerifyFunctions = (-not $script:IsWoW64)

    foreach ($imp in $pe.Imports) {
        $dllLower = $imp.DllName.ToLower()
        $isWsProvided = $dllLower -in ($WIRESHARK_PROVIDED_DLLS | ForEach-Object { $_.ToLower() })

        $result = Find-DllInSearchPath -DllName $imp.DllName -WiresharkPath $wsPath

        if ($result) {
            $ver = $null
            if ($result.Method -ne "api-set" -and (Test-Path $result.Path -ErrorAction SilentlyContinue)) {
                $ver = Get-DllFileVersion -FilePath $result.Path
            }
            $verStr = if ($ver) { " v$ver" } else { "" }
            Write-OK "$($imp.DllName) -> $($result.Path) [$($result.Method)]$verStr"
            $resolved++

            # Verify imported functions exist (only in native 64-bit process)
            if ($canVerifyFunctions -and $result.Method -ne "api-set" -and
                (Test-Path $result.Path -ErrorAction SilentlyContinue) -and $imp.Functions.Count -gt 0) {
                $missingFuncs = @()
                foreach ($fn in $imp.Functions) {
                    if ($fn.Name) {
                        $exists = Test-FunctionInDll -DllPath $result.Path -FunctionName $fn.Name
                        if ($exists -eq $false) {
                            $missingFuncs += $fn.Name
                        }
                    }
                }
                if ($missingFuncs.Count -gt 0) {
                    Write-Fail "  $($missingFuncs.Count) missing function(s) in $($imp.DllName):"
                    $missingFuncs | Select-Object -First 10 | ForEach-Object { Write-Fail "    - $_" }
                    if ($missingFuncs.Count -gt 10) {
                        Write-Fail "    ... and $($missingFuncs.Count - 10) more"
                    }
                    $script:IssuesFound++
                }
            }
        } else {
            if ($isWsProvided) {
                # Wireshark-provided DLL - expected to come from Wireshark's directory
                Write-Info "$($imp.DllName) -> provided by Wireshark at runtime ($($imp.Functions.Count) functions)"
                $wsProvidedNotFound += $imp.DllName
                $resolved++  # Not a failure - Wireshark loads these into its process
            } else {
                Write-Fail "$($imp.DllName) -> NOT FOUND in any search path!"
                $failedDeps += $imp.DllName
                $script:IssuesFound++
            }
        }
    }

    if ($script:IsWoW64) {
        Write-Info "(Function-level verification skipped - 32-bit process cannot inspect 64-bit DLL exports)"
    }

    Write-Host ""
    Write-Info "Dependency resolution: $resolved/$totalImports DLLs resolved"
    if ($wsProvidedNotFound.Count -gt 0 -and -not $wsPath) {
        Write-Info "Wireshark-provided (verified at load time): $($wsProvidedNotFound -join ', ')"
    }
    if ($failedDeps.Count -gt 0) {
        Write-Fail "UNRESOLVED: $($failedDeps -join ', ')"
    }

    $totalFuncs = ($pe.Imports | ForEach-Object { $_.Functions.Count } | Measure-Object -Sum).Sum
    Write-Info "Total imported functions: $totalFuncs"
}

# =====================================================================
# Section 7: DLL Load Test
# =====================================================================
Write-Section "7. DLL Load Test"

if (Test-Path $DllPath) {
    if ($script:IsWoW64 -and $pe -and $pe.Is64Bit) {
        Write-Info "Note: 32-bit process cannot fully load-test a 64-bit DLL"
        Write-Info "Data-file test still works; full load test will be skipped"
    }

    # Test 1: data file (works cross-architecture)
    Write-Info "Test 1: Load as data file (no dependency resolution)..."
    $r = Test-DllLoad -DllPath $DllPath -Flags ([NativeMethods]::LOAD_LIBRARY_AS_DATAFILE -bor [NativeMethods]::LOAD_LIBRARY_AS_IMAGE_RESOURCE)
    if ($r.Success) {
        Write-OK "DLL structure is valid (loads as data file)"
    } else {
        Write-Fail "Cannot load as data file: [$($r.ErrorCode)] $($r.Message)"
        $script:IssuesFound++
    }

    if ($script:IsWoW64 -and $pe -and $pe.Is64Bit) {
        # Skip Tests 2 and 3 - a 32-bit process cannot meaningfully load a 64-bit DLL
        Write-Info "Test 2: Skipped (32-bit process cannot resolve 64-bit imports)"
        Write-Info "Test 3: Skipped (32-bit process cannot execute 64-bit DllMain)"
    } else {
        # Test 2: import resolution (same architecture)
        Write-Info "Test 2: Load with import resolution (no DllMain)..."
        $r = Test-DllLoad -DllPath $DllPath -Flags ([NativeMethods]::DONT_RESOLVE_DLL_REFERENCES)
        if ($r.Success) {
            Write-OK "DLL loads successfully with import resolution"
        } else {
            Write-Fail "Load FAILED: [$($r.ErrorCode)] $($r.Message)"
            switch ($r.ErrorCode) {
                126 { Write-Fail "  ERROR_MOD_NOT_FOUND: a required DLL dependency could not be found"
                      Write-Fail "  Check Section 6 above for unresolved dependencies" }
                127 { Write-Fail "  ERROR_PROC_NOT_FOUND: a required function was not found"
                      Write-Fail "  Likely a VC++ runtime version mismatch"
                      Write-Fail "  Try: https://aka.ms/vs/17/release/vc_redist.x64.exe" }
                193 { Write-Fail "  ERROR_BAD_EXE_FORMAT: architecture mismatch?" }
                  5 { Write-Fail "  ERROR_ACCESS_DENIED: check file permissions or antivirus" }
            }
            $script:IssuesFound++
        }

        # Test 3: full load with Wireshark context
        if ($wsPath) {
            Write-Info "Test 3: Full load with Wireshark DLL search path..."
            $r = Test-DllLoadWithContext -DllPath $DllPath -WiresharkPath $wsPath
            if ($r.Success) {
                Write-OK "DLL loads successfully in Wireshark context!"
            } else {
                Write-Fail "Load FAILED in Wireshark context: [$($r.ErrorCode)] $($r.Message)"
                switch ($r.ErrorCode) {
                    126 { Write-Fail "  A transitive dependency is missing even with Wireshark DLLs in path" }
                    127 { Write-Fail "  Function not found in a dependency - likely runtime version mismatch" }
                }
                $script:IssuesFound++
            }
        } else {
            Write-Info "Test 3: Skipped (Wireshark install path not found)"
        }
    }
}

# =====================================================================
# Section 8: Wireshark Plugin Loading Check
# =====================================================================
Write-Section "8. Wireshark Plugin Loading Check"

if ($wsPath) {
    $tshark = Join-Path $wsPath "tshark.exe"
    if (Test-Path $tshark) {
        Write-Info "Querying Wireshark for loaded plugins (via tshark -G plugins)..."
        try {
            $output = & $tshark -G plugins 2>&1
            $pluginLines = $output | Where-Object { $_ -match "packetcircle" }
            if ($pluginLines) {
                Write-OK "PacketCircle IS listed in Wireshark's plugin registry!"
                $pluginLines | ForEach-Object { Write-Info "  $_" }
            } else {
                Write-Warn "PacketCircle is NOT listed in Wireshark's loaded plugins"
                Write-Info "This means Wireshark either can't find or can't load the DLL"
                $script:WarningsFound++
            }
        } catch {
            Write-Warn "Could not query plugins: $_"
            $script:WarningsFound++
        }
    } else {
        Write-Warn "tshark.exe not found - cannot query loaded plugins"
    }
} else {
    Write-Info "Skipped (Wireshark install path not found)"
}

# =====================================================================
# Section 9: Security & Environment Checks
# =====================================================================
Write-Section "9. Security & Environment Checks"

if (Test-Path $DllPath) {
    # Zone.Identifier (downloaded-from-internet mark)
    try {
        $zoneContent = Get-Content -Path ($DllPath + ":Zone.Identifier") -ErrorAction Stop
        Write-Warn "Plugin DLL has 'downloaded from internet' mark (Zone.Identifier)!"
        $zoneContent | ForEach-Object { Write-Warn "  $_" }
        Write-Warn "FIX: Right-click the DLL -> Properties -> check 'Unblock' -> Apply"
        Write-Warn "Or run:  Unblock-File `"$DllPath`""
        $script:WarningsFound++
    } catch {
        Write-OK "No internet download zone marker (file not blocked)"
    }

    # File owner info
    $acl = Get-Acl $DllPath -ErrorAction SilentlyContinue
    if ($acl) {
        Write-Info "File owner: $($acl.Owner)"
    }
}

Write-Info "If Windows Defender or antivirus is active, it may silently block"
Write-Info "unsigned DLLs. Check your AV quarantine/logs if other checks pass."

# Wireshark config check
$wsConfig = "$env:APPDATA\Wireshark"
if (Test-Path $wsConfig) {
    Write-OK "Wireshark config directory exists: $wsConfig"
    $initLua = Join-Path $wsConfig "init.lua"
    if (Test-Path $initLua) {
        $content = Get-Content $initLua -Raw -ErrorAction SilentlyContinue
        if ($content -and ($content -match "disable_lua|enable_lua\s*=\s*false")) {
            Write-Warn "init.lua may disable Lua/plugins - check if this affects plugin loading"
            $script:WarningsFound++
        }
    }
} else {
    Write-Warn "Wireshark config directory not found: $wsConfig"
    $script:WarningsFound++
}

# =====================================================================
# Summary
# =====================================================================
Write-Section "SUMMARY"

Write-Host ""
if ($script:IsWoW64) {
    Write-Warn "Results may be incomplete (32-bit PowerShell). For full diagnostics use 64-bit:"
    Write-Host "  C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe .\troubleshoot.ps1" -ForegroundColor Yellow
    Write-Host ""
}

if ($script:IssuesFound -eq 0 -and $script:WarningsFound -eq 0) {
    Write-Host "  All checks passed! No issues detected." -ForegroundColor Green
    Write-Host ""
    Write-Host "  If the plugin still doesn't load, try:"
    Write-Host "  1. Restart Wireshark completely"
    Write-Host "  2. Check Help -> About Wireshark -> Plugins tab"
    Write-Host '  3. Run: wireshark -o log.level:debug 2> debug.txt'
} elseif ($script:IssuesFound -gt 0) {
    Write-Host "  Found $($script:IssuesFound) issue(s) and $($script:WarningsFound) warning(s)" -ForegroundColor Red
    Write-Host ""
    Write-Host "  Recommended fixes:"
    Write-Host "  1. Install latest VC++ 2022 Redistributable (x64):"
    Write-Host "     https://aka.ms/vs/17/release/vc_redist.x64.exe"
    Write-Host "  2. Verify plugin is in the correct directory (see Section 4)"
    Write-Host "  3. Right-click DLL -> Properties -> Unblock (if downloaded)"
    Write-Host "  4. Temporarily disable antivirus and retry"
    Write-Host '  5. Run: wireshark -o log.level:debug 2> debug.txt'
} else {
    Write-Host "  No hard issues, but $($script:WarningsFound) warning(s) found" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Review the warnings above. Most common fix:"
    Write-Host "  1. Ensure plugin is in the correct directory (see Section 4)"
    Write-Host "  2. Restart Wireshark after installation"
    Write-Host "  3. Check Help -> About Wireshark -> Plugins tab"
}

Write-Host ""
Write-Host ("=" * 64) -ForegroundColor White
Write-Host ""
Write-Host "  To save this report:  .\troubleshoot.ps1 | Tee-Object report.txt"
Write-Host ""
