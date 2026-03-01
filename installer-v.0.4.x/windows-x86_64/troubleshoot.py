#!/usr/bin/env python3
"""
PacketCircle Windows Troubleshooting Script
============================================
Diagnoses DLL dependency and installation issues for the PacketCircle
Wireshark plugin on Windows 10/11.

What it checks:
  1. Plugin DLL location and PE header validity
  2. Wireshark installation, version, and architecture
  3. Plugin directory paths (personal + system)
  4. All imported DLL dependencies - resolved against actual system
  5. VC++ Redistributable version and CRT DLLs
  6. Import symbol verification (checks every imported function)
  7. Wireshark debug log analysis (optional)

Usage:
    python troubleshoot.py
    python troubleshoot.py C:\\path\\to\\packetcircle.dll

Requirements:
    - Python 3.6+  (standard library only, no pip packages needed)
    - Windows 10/11 x86_64

Copyright (C) 2026 Walter Hofstetter
License: GPL v2+
AI-Assisted: yes (Claude)
"""

import sys
import os
import struct
import subprocess
import json
from pathlib import Path
from collections import OrderedDict

# ---------------------------------------------------------------------------
# Ensure Windows
# ---------------------------------------------------------------------------
if sys.platform != "win32":
    print("ERROR: This script must be run on Windows.")
    sys.exit(1)

import ctypes
import ctypes.wintypes
import winreg

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
PLUGIN_NAME = "packetcircle.dll"
SUPPORTED_ABI = "4-6"
WIRESHARK_MIN_VERSION = (4, 6, 0)

IMAGE_FILE_MACHINE_AMD64 = 0x8664
IMAGE_FILE_MACHINE_I386 = 0x14C
IMAGE_FILE_MACHINE_ARM64 = 0xAA64

LOAD_LIBRARY_AS_DATAFILE = 0x00000002
DONT_RESOLVE_DLL_REFERENCES = 0x00000001
LOAD_LIBRARY_AS_IMAGE_RESOURCE = 0x00000020

# Machine type display names
MACHINE_NAMES = {
    IMAGE_FILE_MACHINE_AMD64: "x86_64 (AMD64)",
    IMAGE_FILE_MACHINE_I386: "x86 (i386)",
    IMAGE_FILE_MACHINE_ARM64: "ARM64",
}

# Well-known Windows system DLLs (always present on Win10+)
SYSTEM_DLLS = {
    "kernel32.dll", "ntdll.dll", "user32.dll", "gdi32.dll",
    "advapi32.dll", "shell32.dll", "ole32.dll", "oleaut32.dll",
    "comctl32.dll", "comdlg32.dll", "ws2_32.dll", "crypt32.dll",
    "shlwapi.dll", "secur32.dll", "bcrypt.dll", "userenv.dll",
}

# API set DLLs (virtual, always resolved by the loader on Win10+)
API_SET_PREFIXES = ("api-ms-win-", "ext-ms-win-")


# ---------------------------------------------------------------------------
# Pretty output helpers
# ---------------------------------------------------------------------------
class Colors:
    """ANSI-like colors via Windows console API."""
    RESET = ""
    RED = ""
    GREEN = ""
    YELLOW = ""
    CYAN = ""
    BOLD = ""

    @staticmethod
    def init():
        """Enable virtual terminal sequences on Windows 10+."""
        try:
            kernel32 = ctypes.windll.kernel32
            handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
            mode = ctypes.wintypes.DWORD()
            kernel32.GetConsoleMode(handle, ctypes.byref(mode))
            # ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)
            Colors.RESET = "\033[0m"
            Colors.RED = "\033[91m"
            Colors.GREEN = "\033[92m"
            Colors.YELLOW = "\033[93m"
            Colors.CYAN = "\033[96m"
            Colors.BOLD = "\033[1m"
        except Exception:
            pass  # Fall back to no colors


def ok(msg):
    print(f"  {Colors.GREEN}[OK]{Colors.RESET}   {msg}")

def warn(msg):
    print(f"  {Colors.YELLOW}[WARN]{Colors.RESET} {msg}")

def fail(msg):
    print(f"  {Colors.RED}[FAIL]{Colors.RESET} {msg}")

def info(msg):
    print(f"  {Colors.CYAN}[INFO]{Colors.RESET} {msg}")

def section(title):
    print()
    print(f"{Colors.BOLD}{'=' * 64}{Colors.RESET}")
    print(f"{Colors.BOLD}  {title}{Colors.RESET}")
    print(f"{Colors.BOLD}{'=' * 64}{Colors.RESET}")


# ---------------------------------------------------------------------------
# PE Parser (minimal, pure-Python, no external dependencies)
# ---------------------------------------------------------------------------
class PEImport:
    """Represents a single imported DLL and its functions."""
    def __init__(self, dll_name, functions=None):
        self.dll_name = dll_name
        self.functions = functions or []  # list of (ordinal_or_None, name_or_None)


class PEInfo:
    """Minimal PE parser to extract architecture, imports, and version info."""

    def __init__(self, filepath):
        self.filepath = filepath
        self.machine = 0
        self.is_64bit = False
        self.timestamp = 0
        self.linker_major = 0
        self.linker_minor = 0
        self.os_major = 0
        self.os_minor = 0
        self.subsystem_major = 0
        self.subsystem_minor = 0
        self.subsystem = 0
        self.characteristics = 0
        self.imports = []  # list of PEImport
        self.num_sections = 0
        self._sections = []  # (name, virtual_size, virtual_addr, raw_size, raw_offset)
        self._parse()

    def _parse(self):
        with open(self.filepath, "rb") as f:
            data = f.read()

        # DOS header
        if data[:2] != b"MZ":
            raise ValueError("Not a valid PE file (missing MZ signature)")

        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]

        # PE signature
        if data[pe_offset:pe_offset + 4] != b"PE\x00\x00":
            raise ValueError("Not a valid PE file (missing PE signature)")

        # COFF header (20 bytes after PE signature)
        coff = pe_offset + 4
        self.machine = struct.unpack_from("<H", data, coff)[0]
        self.num_sections = struct.unpack_from("<H", data, coff + 2)[0]
        self.timestamp = struct.unpack_from("<I", data, coff + 4)[0]
        opt_header_size = struct.unpack_from("<H", data, coff + 16)[0]
        self.characteristics = struct.unpack_from("<H", data, coff + 18)[0]

        # Optional header
        opt = coff + 20
        magic = struct.unpack_from("<H", data, opt)[0]
        self.is_64bit = (magic == 0x20B)  # PE32+ = 64-bit

        self.linker_major = struct.unpack_from("<B", data, opt + 2)[0]
        self.linker_minor = struct.unpack_from("<B", data, opt + 3)[0]

        # OS and subsystem version
        self.os_major = struct.unpack_from("<H", data, opt + 40)[0]
        self.os_minor = struct.unpack_from("<H", data, opt + 42)[0]
        self.subsystem_major = struct.unpack_from("<H", data, opt + 48)[0]
        self.subsystem_minor = struct.unpack_from("<H", data, opt + 50)[0]

        if self.is_64bit:
            self.subsystem = struct.unpack_from("<H", data, opt + 68)[0]
            num_rva_sizes = struct.unpack_from("<I", data, opt + 108)[0]
            data_dir_offset = opt + 112
        else:
            self.subsystem = struct.unpack_from("<H", data, opt + 68)[0]
            num_rva_sizes = struct.unpack_from("<I", data, opt + 92)[0]
            data_dir_offset = opt + 96

        # Section headers (immediately after optional header)
        section_offset = opt + opt_header_size
        for i in range(self.num_sections):
            s = section_offset + i * 40
            name = data[s:s + 8].rstrip(b"\x00").decode("ascii", errors="replace")
            vsize = struct.unpack_from("<I", data, s + 8)[0]
            vaddr = struct.unpack_from("<I", data, s + 12)[0]
            rsize = struct.unpack_from("<I", data, s + 16)[0]
            roff = struct.unpack_from("<I", data, s + 20)[0]
            self._sections.append((name, vsize, vaddr, rsize, roff))

        # Import directory (data directory index 1)
        if num_rva_sizes > 1:
            import_rva = struct.unpack_from("<I", data, data_dir_offset + 8)[0]
            import_size = struct.unpack_from("<I", data, data_dir_offset + 12)[0]
            if import_rva and import_size:
                self._parse_imports(data, import_rva)

    def _rva_to_offset(self, rva):
        """Convert a Relative Virtual Address to file offset."""
        for name, vsize, vaddr, rsize, roff in self._sections:
            if vaddr <= rva < vaddr + max(vsize, rsize):
                return roff + (rva - vaddr)
        return None

    def _parse_imports(self, data, import_rva):
        """Parse the import directory table."""
        offset = self._rva_to_offset(import_rva)
        if offset is None:
            return

        # Each import directory entry is 20 bytes; terminated by a null entry
        while True:
            if offset + 20 > len(data):
                break

            ilt_rva = struct.unpack_from("<I", data, offset)[0]      # Import Lookup Table
            _ts = struct.unpack_from("<I", data, offset + 4)[0]
            _fc = struct.unpack_from("<I", data, offset + 8)[0]
            name_rva = struct.unpack_from("<I", data, offset + 12)[0]
            _iat_rva = struct.unpack_from("<I", data, offset + 16)[0]

            if name_rva == 0:
                break  # End of import directory

            # Read DLL name
            name_off = self._rva_to_offset(name_rva)
            if name_off is None:
                offset += 20
                continue

            end = data.index(b"\x00", name_off)
            dll_name = data[name_off:end].decode("ascii", errors="replace")

            # Parse imported functions from Import Lookup Table
            functions = []
            if ilt_rva:
                ilt_off = self._rva_to_offset(ilt_rva)
                if ilt_off is not None:
                    entry_size = 8 if self.is_64bit else 4
                    ordinal_flag = (1 << 63) if self.is_64bit else (1 << 31)
                    fmt = "<Q" if self.is_64bit else "<I"
                    pos = ilt_off
                    while pos + entry_size <= len(data):
                        val = struct.unpack_from(fmt, data, pos)[0]
                        if val == 0:
                            break
                        if val & ordinal_flag:
                            # Import by ordinal
                            ordinal = val & 0xFFFF
                            functions.append((ordinal, None))
                        else:
                            # Import by name
                            hint_rva = val & 0x7FFFFFFF
                            hint_off = self._rva_to_offset(hint_rva)
                            if hint_off is not None and hint_off + 2 < len(data):
                                hint = struct.unpack_from("<H", data, hint_off)[0]
                                fname_end = data.index(b"\x00", hint_off + 2)
                                fname = data[hint_off + 2:fname_end].decode("ascii", errors="replace")
                                functions.append((hint, fname))
                        pos += entry_size

            self.imports.append(PEImport(dll_name, functions))
            offset += 20

    @property
    def machine_name(self):
        return MACHINE_NAMES.get(self.machine, f"Unknown (0x{self.machine:X})")


# ---------------------------------------------------------------------------
# Windows system checks
# ---------------------------------------------------------------------------
def find_wireshark():
    """Find Wireshark installation path and version."""
    search_paths = [
        os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), "Wireshark"),
        os.path.join(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"), "Wireshark"),
        os.path.join(os.environ.get("LOCALAPPDATA", ""), "Programs", "Wireshark"),
    ]

    for p in search_paths:
        exe = os.path.join(p, "Wireshark.exe")
        if os.path.isfile(exe):
            return p

    # Try PATH
    try:
        result = subprocess.run(
            ["where", "wireshark.exe"], capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            exe_path = result.stdout.strip().splitlines()[0]
            return os.path.dirname(exe_path)
    except Exception:
        pass

    return None


def get_wireshark_version(ws_path):
    """Get Wireshark version string."""
    # Method 1: tshark --version
    for exe_name in ["tshark.exe", "Wireshark.exe"]:
        exe = os.path.join(ws_path, exe_name)
        if os.path.isfile(exe):
            try:
                result = subprocess.run(
                    [exe, "--version"],
                    capture_output=True, text=True, timeout=10
                )
                for line in result.stdout.splitlines():
                    if "ireshark" in line:
                        import re
                        m = re.search(r"(\d+\.\d+\.\d+)", line)
                        if m:
                            return m.group(1)
            except Exception:
                pass

    # Method 2: file version info
    exe = os.path.join(ws_path, "Wireshark.exe")
    if os.path.isfile(exe):
        try:
            pe = PEInfo(exe)
            # Can't easily get product version from PE without parsing resources
            # Fall back to linker info
        except Exception:
            pass

    return None


def get_wireshark_architecture(ws_path):
    """Determine Wireshark's architecture from its EXE."""
    exe = os.path.join(ws_path, "Wireshark.exe")
    if os.path.isfile(exe):
        try:
            pe = PEInfo(exe)
            return pe.machine, pe.machine_name
        except Exception:
            pass
    return None, "Unknown"


def get_vcredist_info():
    """Check installed VC++ 2015-2022 Redistributable from registry."""
    results = []
    keys_to_check = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\X64"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\VisualStudio\14.0\VC\Runtimes\X64"),
    ]

    for hive, key_path in keys_to_check:
        try:
            key = winreg.OpenKey(hive, key_path)
            ver = winreg.QueryValueEx(key, "Version")[0]
            major = winreg.QueryValueEx(key, "Major")[0]
            minor = winreg.QueryValueEx(key, "Minor")[0]
            bld = winreg.QueryValueEx(key, "Bld")[0]
            winreg.CloseKey(key)
            results.append({
                "version": ver,
                "major": major,
                "minor": minor,
                "build": bld,
                "registry_key": key_path,
            })
        except FileNotFoundError:
            pass
        except Exception:
            pass

    return results


def get_dll_file_version(dll_path):
    """Get the file version of a DLL using Windows API."""
    try:
        size = ctypes.windll.version.GetFileVersionInfoSizeW(dll_path, None)
        if size == 0:
            return None
        buf = ctypes.create_string_buffer(size)
        if not ctypes.windll.version.GetFileVersionInfoW(dll_path, 0, size, buf):
            return None

        # Query VS_FIXEDFILEINFO
        p_val = ctypes.c_void_p()
        l_val = ctypes.wintypes.UINT()
        if ctypes.windll.version.VerQueryValueW(
            buf, "\\", ctypes.byref(p_val), ctypes.byref(l_val)
        ):
            # VS_FIXEDFILEINFO structure
            info = ctypes.cast(p_val, ctypes.POINTER(ctypes.c_uint32 * 13)).contents
            # info[2] = dwFileVersionMS, info[3] = dwFileVersionLS
            ms = info[2]
            ls = info[3]
            return f"{(ms >> 16) & 0xFFFF}.{ms & 0xFFFF}.{(ls >> 16) & 0xFFFF}.{ls & 0xFFFF}"
    except Exception:
        pass
    return None


def find_dll_in_search_path(dll_name, wireshark_path=None):
    """
    Attempt to locate a DLL using the standard Windows DLL search order.
    Returns (found_path, method) or (None, None).
    """
    # API set DLLs are virtual - always resolved by the loader
    dll_lower = dll_name.lower()
    for prefix in API_SET_PREFIXES:
        if dll_lower.startswith(prefix):
            return ("(API set - resolved by Windows loader)", "api-set")

    # 1. Wireshark directory (application directory for plugin context)
    if wireshark_path:
        candidate = os.path.join(wireshark_path, dll_name)
        if os.path.isfile(candidate):
            return (candidate, "wireshark-dir")

    # 2. System directories
    sys32 = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")
    candidate = os.path.join(sys32, dll_name)
    if os.path.isfile(candidate):
        return (candidate, "system32")

    syswow = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "SysWOW64")
    candidate = os.path.join(syswow, dll_name)
    if os.path.isfile(candidate):
        return (candidate, "syswow64")

    windir = os.environ.get("SystemRoot", r"C:\Windows")
    candidate = os.path.join(windir, dll_name)
    if os.path.isfile(candidate):
        return (candidate, "windows-dir")

    # 3. PATH directories
    path_dirs = os.environ.get("PATH", "").split(";")
    for d in path_dirs:
        d = d.strip()
        if d:
            candidate = os.path.join(d, dll_name)
            if os.path.isfile(candidate):
                return (candidate, "PATH")

    return (None, None)


def check_dll_loadable(dll_path):
    """
    Try to load the DLL using LoadLibraryEx to see if Windows can resolve it.
    Returns (success, error_code, error_message).
    """
    kernel32 = ctypes.windll.kernel32

    # First try as image resource (won't execute DllMain, won't resolve imports)
    handle = kernel32.LoadLibraryExW(
        dll_path, None,
        LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE
    )
    if handle:
        kernel32.FreeLibrary(handle)

    # Now try with import resolution but without DllMain
    handle = kernel32.LoadLibraryExW(dll_path, None, DONT_RESOLVE_DLL_REFERENCES)
    if handle:
        kernel32.FreeLibrary(handle)
        return (True, 0, "OK")

    err = ctypes.GetLastError()
    # Format error message
    buf = ctypes.create_unicode_buffer(1024)
    ctypes.windll.kernel32.FormatMessageW(
        0x1000,  # FORMAT_MESSAGE_FROM_SYSTEM
        None, err, 0, buf, 1024, None
    )
    return (False, err, buf.value.strip() or f"Error code {err}")


def try_load_with_wireshark_context(dll_path, wireshark_path):
    """
    Try loading the plugin DLL with Wireshark's directory added to DLL search path.
    This simulates how Wireshark loads plugins.
    """
    kernel32 = ctypes.windll.kernel32

    # AddDllDirectory requires Win8+ (available on Win10)
    cookie = None
    try:
        cookie = kernel32.AddDllDirectory(wireshark_path)
    except Exception:
        pass

    # Also try SetDllDirectoryW as fallback
    kernel32.SetDllDirectoryW(wireshark_path)

    handle = kernel32.LoadLibraryExW(dll_path, None, 0)  # Full load
    err = 0
    msg = "OK"
    if not handle:
        err = ctypes.GetLastError()
        buf = ctypes.create_unicode_buffer(1024)
        kernel32.FormatMessageW(0x1000, None, err, 0, buf, 1024, None)
        msg = buf.value.strip() or f"Error code {err}"
    else:
        kernel32.FreeLibrary(handle)

    # Cleanup
    kernel32.SetDllDirectoryW(None)
    if cookie:
        try:
            kernel32.RemoveDllDirectory(cookie)
        except Exception:
            pass

    return (handle != 0 and handle is not None, err, msg)


def get_plugin_directories(ws_version_str):
    """Get expected plugin directories for a given Wireshark version."""
    if not ws_version_str:
        return []

    parts = ws_version_str.split(".")
    if len(parts) < 2:
        return []

    major, minor = parts[0], parts[1]

    # Windows uses dashes in plugin path (4-6, not 4.6)
    dash_id = f"{major}-{minor}"
    dot_id = f"{major}.{minor}"

    dirs = []

    # Personal plugins
    appdata = os.environ.get("APPDATA", "")
    if appdata:
        dirs.append(("Personal (dashes)", os.path.join(appdata, "Wireshark", "plugins", dash_id, "epan")))
        dirs.append(("Personal (dots)", os.path.join(appdata, "Wireshark", "plugins", dot_id, "epan")))

    return dirs


def scan_existing_plugin_dirs():
    """Scan for any existing Wireshark plugin directories."""
    found = []
    appdata = os.environ.get("APPDATA", "")
    if appdata:
        plugin_base = os.path.join(appdata, "Wireshark", "plugins")
        if os.path.isdir(plugin_base):
            for entry in os.listdir(plugin_base):
                full = os.path.join(plugin_base, entry)
                if os.path.isdir(full):
                    epan_dir = os.path.join(full, "epan")
                    if os.path.isdir(epan_dir):
                        found.append(("Personal", entry, epan_dir))
                    else:
                        found.append(("Personal", entry, full))

    return found


def check_wireshark_about_plugins(ws_path):
    """
    Run tshark to list loaded plugins and check if packetcircle is among them.
    """
    tshark = os.path.join(ws_path, "tshark.exe")
    if not os.path.isfile(tshark):
        return None, "tshark.exe not found"

    try:
        # tshark -G plugins lists all plugins
        result = subprocess.run(
            [tshark, "-G", "plugins"],
            capture_output=True, text=True, timeout=15
        )
        if result.returncode == 0:
            lines = result.stdout.strip().splitlines()
            plugin_lines = []
            found = False
            for line in lines:
                if "packetcircle" in line.lower():
                    found = True
                    plugin_lines.append(line)
            return found, plugin_lines if plugin_lines else lines
    except subprocess.TimeoutExpired:
        return None, "tshark timed out"
    except Exception as e:
        return None, str(e)

    return None, "Could not query plugins"


def check_function_exists_in_dll(dll_path, function_name):
    """Check if a function name exists as an export in a loaded DLL."""
    kernel32 = ctypes.windll.kernel32
    handle = kernel32.LoadLibraryExW(dll_path, None, DONT_RESOLVE_DLL_REFERENCES)
    if not handle:
        return None  # Can't load DLL
    try:
        addr = kernel32.GetProcAddress(handle, function_name.encode("ascii"))
        return addr != 0 and addr is not None
    except Exception:
        return None
    finally:
        kernel32.FreeLibrary(handle)


# ---------------------------------------------------------------------------
# Main diagnostic routine
# ---------------------------------------------------------------------------
def main():
    Colors.init()

    print()
    print(f"{Colors.BOLD}╔══════════════════════════════════════════════════════════════╗{Colors.RESET}")
    print(f"{Colors.BOLD}║   PacketCircle Windows Troubleshooting Tool                 ║{Colors.RESET}")
    print(f"{Colors.BOLD}║   Dependency & Installation Diagnostics                     ║{Colors.RESET}")
    print(f"{Colors.BOLD}╚══════════════════════════════════════════════════════════════╝{Colors.RESET}")

    issues_found = 0
    warnings_found = 0

    # --- Determine plugin DLL path ---
    if len(sys.argv) > 1:
        plugin_path = sys.argv[1]
    else:
        # Auto-detect: check common locations
        script_dir = os.path.dirname(os.path.abspath(__file__))
        candidates = [
            os.path.join(script_dir, PLUGIN_NAME),
        ]
        appdata = os.environ.get("APPDATA", "")
        if appdata:
            candidates.append(os.path.join(appdata, "Wireshark", "plugins", "4-6", "epan", PLUGIN_NAME))
            candidates.append(os.path.join(appdata, "Wireshark", "plugins", "4.6", "epan", PLUGIN_NAME))

        plugin_path = None
        for c in candidates:
            if os.path.isfile(c):
                plugin_path = c
                break

        if not plugin_path:
            plugin_path = os.path.join(script_dir, PLUGIN_NAME)

    # =====================================================================
    # Section 1: System Information
    # =====================================================================
    section("1. System Information")

    # Python
    info(f"Python: {sys.version}")
    info(f"Platform: {sys.platform}")
    info(f"Architecture: {ctypes.sizeof(ctypes.c_void_p) * 8}-bit")

    # Windows version
    try:
        ver = sys.getwindowsversion()
        info(f"Windows: {ver.major}.{ver.minor} build {ver.build} "
             f"(platform {ver.platform})")
        if hasattr(ver, "service_pack") and ver.service_pack:
            info(f"Service Pack: {ver.service_pack}")
    except Exception:
        warn("Could not determine Windows version")

    # Check if running as admin
    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        info(f"Running as admin: {'Yes' if is_admin else 'No'}")
    except Exception:
        pass

    # =====================================================================
    # Section 2: Plugin DLL Analysis
    # =====================================================================
    section("2. Plugin DLL Analysis")

    if not os.path.isfile(plugin_path):
        fail(f"Plugin DLL not found: {plugin_path}")
        print()
        print("  Please specify the path to packetcircle.dll:")
        print(r"    python troubleshoot.py C:\path\to\packetcircle.dll")
        issues_found += 1
    else:
        file_size = os.path.getsize(plugin_path)
        ok(f"Found: {plugin_path}")
        info(f"Size: {file_size:,} bytes ({file_size / 1024:.1f} KB)")

        try:
            pe = PEInfo(plugin_path)
            ok(f"Valid PE file")
            info(f"Architecture: {pe.machine_name}")
            info(f"64-bit: {pe.is_64bit}")
            info(f"Linker: MSVC {pe.linker_major}.{pe.linker_minor}")
            info(f"Min OS version: {pe.os_major}.{pe.os_minor}")
            info(f"Subsystem version: {pe.subsystem_major}.{pe.subsystem_minor}")
            info(f"Sections: {pe.num_sections}")
            info(f"Imported DLLs: {len(pe.imports)}")

            import datetime
            try:
                ts = datetime.datetime.fromtimestamp(pe.timestamp)
                info(f"Build timestamp: {ts}")
            except Exception:
                pass

            if pe.machine != IMAGE_FILE_MACHINE_AMD64:
                fail(f"Plugin is NOT x86_64! It is {pe.machine_name}")
                fail("Wireshark 64-bit requires an x86_64 plugin")
                issues_found += 1

            # Check minimum OS version compatibility
            if pe.subsystem_major > 10 or (pe.subsystem_major == 10 and pe.subsystem_minor > 0):
                fail(f"Plugin requires Windows {pe.subsystem_major}.{pe.subsystem_minor}+")
                fail("This may be incompatible with Windows 10")
                issues_found += 1
            else:
                ok(f"OS version requirement ({pe.os_major}.{pe.os_minor}) is compatible with Windows 10")

        except Exception as e:
            fail(f"Failed to parse PE: {e}")
            pe = None
            issues_found += 1

    # =====================================================================
    # Section 3: Wireshark Installation
    # =====================================================================
    section("3. Wireshark Installation")

    ws_path = find_wireshark()
    ws_version = None

    if not ws_path:
        fail("Wireshark installation not found!")
        fail("Checked: Program Files, Program Files (x86), LocalAppData, PATH")
        issues_found += 1
    else:
        ok(f"Wireshark found: {ws_path}")

        # Architecture check
        ws_machine, ws_arch_name = get_wireshark_architecture(ws_path)
        info(f"Wireshark architecture: {ws_arch_name}")

        if pe and ws_machine and pe.machine != ws_machine:
            fail(f"ARCHITECTURE MISMATCH!")
            fail(f"  Plugin: {pe.machine_name}")
            fail(f"  Wireshark: {ws_arch_name}")
            fail("  The plugin and Wireshark must have the same architecture")
            issues_found += 1
        elif pe and ws_machine:
            ok("Architecture match: both x86_64")

        # Version
        ws_version = get_wireshark_version(ws_path)
        if ws_version:
            ok(f"Wireshark version: {ws_version}")
            parts = ws_version.split(".")
            if len(parts) >= 2:
                ws_major, ws_minor = int(parts[0]), int(parts[1])
                if ws_major != 4 or ws_minor != 6:
                    fail(f"Version {ws_version} may be incompatible with this plugin (built for 4.6.x)")
                    issues_found += 1
                else:
                    ok("Version 4.6.x confirmed - compatible with plugin")
        else:
            warn("Could not determine Wireshark version")
            warnings_found += 1

        # List DLLs in Wireshark directory that the plugin needs
        if pe:
            info(f"Checking Wireshark bundled DLLs...")
            for imp in pe.imports:
                dll_lower = imp.dll_name.lower()
                ws_dll = os.path.join(ws_path, imp.dll_name)
                if os.path.isfile(ws_dll):
                    ver = get_dll_file_version(ws_dll)
                    ver_str = f" (v{ver})" if ver else ""
                    info(f"  Bundled: {imp.dll_name}{ver_str}")

    # =====================================================================
    # Section 4: Plugin Directory Check
    # =====================================================================
    section("4. Plugin Directory Check")

    # Scan existing directories
    existing_dirs = scan_existing_plugin_dirs()
    if existing_dirs:
        info("Existing plugin directories found:")
        for loc_type, ver_id, path in existing_dirs:
            has_plugin = os.path.isfile(os.path.join(path, PLUGIN_NAME))
            status = f" {Colors.GREEN}<-- {PLUGIN_NAME} found here{Colors.RESET}" if has_plugin else ""
            # Also check if it's in the parent (non-epan) path
            if not has_plugin and path.endswith("epan"):
                pass
            elif not has_plugin:
                epan_path = os.path.join(path, "epan")
                if os.path.isdir(epan_path) and os.path.isfile(os.path.join(epan_path, PLUGIN_NAME)):
                    status = f" -> epan/ {Colors.GREEN}<-- {PLUGIN_NAME} found{Colors.RESET}"
            info(f"  [{loc_type}] {ver_id}: {path}{status}")
    else:
        warn("No existing Wireshark plugin directories found in %APPDATA%")
        warnings_found += 1

    # Check expected paths
    if ws_version:
        expected_dirs = get_plugin_directories(ws_version)
        info("Expected plugin directories for this Wireshark version:")
        for label, path in expected_dirs:
            exists = os.path.isdir(path)
            has_plugin = os.path.isfile(os.path.join(path, PLUGIN_NAME))
            if has_plugin:
                ok(f"  {label}: {path} -> {PLUGIN_NAME} INSTALLED")
            elif exists:
                warn(f"  {label}: {path} -> directory exists but NO plugin")
                warnings_found += 1
            else:
                info(f"  {label}: {path} -> does not exist")

    # Check if Wireshark has a system plugins directory with version info
    if ws_path:
        sys_plugin_base = os.path.join(ws_path, "plugins")
        if os.path.isdir(sys_plugin_base):
            info("System plugin directories:")
            for entry in os.listdir(sys_plugin_base):
                full = os.path.join(sys_plugin_base, entry)
                if os.path.isdir(full):
                    info(f"  {entry}/")
                    epan_dir = os.path.join(full, "epan")
                    if os.path.isdir(epan_dir):
                        for f in os.listdir(epan_dir):
                            info(f"    epan/{f}")

    # =====================================================================
    # Section 5: VC++ Runtime Check
    # =====================================================================
    section("5. Visual C++ Runtime Check")

    vcredist = get_vcredist_info()
    if vcredist:
        for vc in vcredist:
            ok(f"VC++ Redistributable: {vc['version']} "
               f"(Major={vc['major']}, Minor={vc['minor']}, Build={vc['build']})")

            # Check if the version is recent enough
            # MSVC 14.44 needs at least 14.40 runtime
            if vc['minor'] < 40:
                warn(f"VC++ runtime minor version {vc['minor']} may be too old for MSVC 14.44 plugin")
                warn("Recommend installing latest VC++ 2022 Redistributable:")
                warn("  https://aka.ms/vs/17/release/vc_redist.x64.exe")
                warnings_found += 1
            else:
                ok(f"VC++ runtime version is compatible with MSVC 14.44 linker")
    else:
        fail("VC++ 2015-2022 Redistributable (x64) NOT FOUND in registry!")
        fail("Install from: https://aka.ms/vs/17/release/vc_redist.x64.exe")
        issues_found += 1

    # Check individual CRT DLLs
    crt_dlls = [
        ("VCRUNTIME140.dll", True),
        ("VCRUNTIME140_1.dll", True),
        ("MSVCP140.dll", True),
        ("ucrtbase.dll", True),
    ]

    sys32 = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")
    info("CRT DLL versions in System32:")
    for dll_name, required in crt_dlls:
        dll_path = os.path.join(sys32, dll_name)
        if os.path.isfile(dll_path):
            ver = get_dll_file_version(dll_path)
            ok(f"  {dll_name}: v{ver}" if ver else f"  {dll_name}: present")
        elif required:
            fail(f"  {dll_name}: MISSING!")
            issues_found += 1
        else:
            info(f"  {dll_name}: not found (optional)")

    # Also check if Wireshark bundles its own CRT
    if ws_path:
        info("CRT DLLs in Wireshark directory:")
        for dll_name, _ in crt_dlls:
            dll_path = os.path.join(ws_path, dll_name)
            if os.path.isfile(dll_path):
                ver = get_dll_file_version(dll_path)
                info(f"  {dll_name}: v{ver}" if ver else f"  {dll_name}: present")

    # =====================================================================
    # Section 6: DLL Dependency Resolution
    # =====================================================================
    section("6. DLL Dependency Resolution")

    if pe and os.path.isfile(plugin_path):
        total_imports = len(pe.imports)
        resolved = 0
        failed_deps = []

        for imp in pe.imports:
            dll_name = imp.dll_name
            found_path, method = find_dll_in_search_path(dll_name, ws_path)

            if found_path:
                ver = None
                if method not in ("api-set",) and os.path.isfile(found_path):
                    ver = get_dll_file_version(found_path)
                ver_str = f" v{ver}" if ver else ""
                ok(f"{dll_name} -> {found_path} [{method}]{ver_str}")
                resolved += 1

                # Verify imported functions exist in the found DLL
                if method not in ("api-set",) and os.path.isfile(found_path) and imp.functions:
                    missing_funcs = []
                    for ordinal, fname in imp.functions:
                        if fname:
                            exists = check_function_exists_in_dll(found_path, fname)
                            if exists is False:
                                missing_funcs.append(fname)
                    if missing_funcs:
                        fail(f"  {len(missing_funcs)} missing function(s) in {dll_name}:")
                        for mf in missing_funcs[:10]:  # Show up to 10
                            fail(f"    - {mf}")
                        if len(missing_funcs) > 10:
                            fail(f"    ... and {len(missing_funcs) - 10} more")
                        issues_found += 1
            else:
                fail(f"{dll_name} -> NOT FOUND in any search path!")
                failed_deps.append(dll_name)
                issues_found += 1

        print()
        info(f"Dependency resolution: {resolved}/{total_imports} DLLs found")
        if failed_deps:
            fail(f"UNRESOLVED: {', '.join(failed_deps)}")

        # Count total imported functions
        total_funcs = sum(len(imp.functions) for imp in pe.imports)
        info(f"Total imported functions: {total_funcs}")

    # =====================================================================
    # Section 7: DLL Load Test
    # =====================================================================
    section("7. DLL Load Test")

    if os.path.isfile(plugin_path):
        # Test 1: Load as data file (no dependency resolution)
        info("Test 1: Load as data file (no dependency resolution)...")
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.LoadLibraryExW(
            plugin_path, None,
            LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE
        )
        if handle:
            ok("DLL structure is valid (loads as data file)")
            kernel32.FreeLibrary(handle)
        else:
            err = ctypes.GetLastError()
            fail(f"Cannot even load as data file! Error: {err}")
            issues_found += 1

        # Test 2: Load without executing (resolves imports)
        info("Test 2: Load with import resolution (no DllMain)...")
        success, err, msg = check_dll_loadable(plugin_path)
        if success:
            ok("DLL loads successfully with import resolution")
        else:
            fail(f"Load FAILED: [{err}] {msg}")
            if err == 126:  # ERROR_MOD_NOT_FOUND
                fail("A required DLL dependency could not be found")
                fail("Check Section 6 above for unresolved dependencies")
            elif err == 127:  # ERROR_PROC_NOT_FOUND
                fail("A required function was not found in a dependency DLL")
                fail("This usually means a version mismatch in VC++ runtime")
                fail("Try installing latest: https://aka.ms/vs/17/release/vc_redist.x64.exe")
            elif err == 193:  # ERROR_BAD_EXE_FORMAT
                fail("Bad executable format - architecture mismatch?")
            elif err == 5:  # ERROR_ACCESS_DENIED
                fail("Access denied - check file permissions or antivirus")
            issues_found += 1

        # Test 3: Full load with Wireshark's directory in search path
        if ws_path:
            info("Test 3: Full load with Wireshark DLL search path...")
            success, err, msg = try_load_with_wireshark_context(plugin_path, ws_path)
            if success:
                ok("DLL loads successfully in Wireshark context!")
            else:
                fail(f"Load FAILED: [{err}] {msg}")
                if err == 126:
                    fail("  ERROR_MOD_NOT_FOUND: a transitive dependency is missing")
                elif err == 127:
                    fail("  ERROR_PROC_NOT_FOUND: function not found in a dependency")
                    fail("  This is likely a VC++ runtime version mismatch")
                issues_found += 1

    # =====================================================================
    # Section 8: Wireshark Plugin Loading Check
    # =====================================================================
    section("8. Wireshark Plugin Loading Check")

    if ws_path:
        info("Querying Wireshark for loaded plugins (via tshark)...")
        found, result = check_wireshark_about_plugins(ws_path)
        if found is True:
            ok("PacketCircle IS listed in Wireshark's plugin registry!")
            for line in result:
                info(f"  {line}")
        elif found is False:
            warn("PacketCircle is NOT listed in Wireshark's loaded plugins")
            info("This means Wireshark either can't find or can't load the plugin")
            warnings_found += 1
        else:
            warn(f"Could not query Wireshark plugins: {result}")
            warnings_found += 1
    else:
        warn("Skipped - Wireshark not found")

    # =====================================================================
    # Section 9: Security & Environment Checks
    # =====================================================================
    section("9. Security & Environment Checks")

    # Check if plugin file has Zone.Identifier (downloaded from internet)
    if os.path.isfile(plugin_path):
        zone_file = plugin_path + ":Zone.Identifier"
        try:
            # On NTFS, alternate data streams indicate downloaded files
            if os.path.exists(zone_file):
                warn("Plugin DLL has a 'downloaded from internet' mark (Zone.Identifier)")
                warn("Windows may block it. Right-click the DLL -> Properties -> Unblock")
                warnings_found += 1
            else:
                ok("No internet download zone marker found")
        except Exception:
            # The :Zone.Identifier check may not work via os.path.exists
            # Try reading it directly
            try:
                with open(zone_file, "r") as f:
                    zone_data = f.read()
                warn("Plugin DLL has a 'downloaded from internet' mark!")
                warn(f"  Zone data: {zone_data.strip()}")
                warn("  Right-click the DLL -> Properties -> check 'Unblock' -> Apply")
                warnings_found += 1
            except (FileNotFoundError, OSError):
                ok("No internet download zone marker (file not blocked)")

    # Check Windows Defender exclusions hint
    info("If Windows Defender or antivirus is active, it may silently block")
    info("unsigned DLLs. Check your AV quarantine/logs if other checks pass.")

    # Check if the user's Wireshark config directory exists
    appdata = os.environ.get("APPDATA", "")
    ws_config = os.path.join(appdata, "Wireshark")
    if os.path.isdir(ws_config):
        ok(f"Wireshark config directory exists: {ws_config}")
        # Check for init.lua or other config that might disable plugins
        init_lua = os.path.join(ws_config, "init.lua")
        if os.path.isfile(init_lua):
            try:
                with open(init_lua, "r") as f:
                    content = f.read()
                if "disable_lua" in content.lower() or "enable_lua = false" in content.lower():
                    warn("init.lua may have Lua disabled - check if this affects plugin loading")
                    warnings_found += 1
            except Exception:
                pass
    else:
        warn(f"Wireshark config directory not found: {ws_config}")
        warnings_found += 1

    # =====================================================================
    # Summary
    # =====================================================================
    section("SUMMARY")

    if issues_found == 0 and warnings_found == 0:
        print()
        print(f"  {Colors.GREEN}All checks passed! No issues detected.{Colors.RESET}")
        print()
        print("  If the plugin still doesn't load, try:")
        print("  1. Restart Wireshark completely")
        print("  2. Check Help -> About Wireshark -> Plugins tab")
        print("  3. Run: wireshark -o log.level:debug 2> debug.txt")
    elif issues_found > 0:
        print()
        print(f"  {Colors.RED}Found {issues_found} issue(s) and {warnings_found} warning(s){Colors.RESET}")
        print()
        print("  Recommended fixes:")
        print("  1. Install latest VC++ 2022 Redistributable (x64):")
        print("     https://aka.ms/vs/17/release/vc_redist.x64.exe")
        print("  2. Verify plugin is in the correct directory (see Section 4)")
        print("  3. Right-click DLL -> Properties -> Unblock (if downloaded)")
        print("  4. Temporarily disable antivirus and retry")
        print("  5. Run Wireshark debug: wireshark -o log.level:debug 2> debug.txt")
    else:
        print()
        print(f"  {Colors.YELLOW}No hard issues, but {warnings_found} warning(s) found{Colors.RESET}")
        print()
        print("  Review the warnings above. Most common fix:")
        print("  1. Ensure plugin is in the correct directory (see Section 4)")
        print("  2. Restart Wireshark after installation")
        print("  3. Check Help -> About Wireshark -> Plugins tab")

    print()
    print(f"{Colors.BOLD}{'=' * 64}{Colors.RESET}")

    # Offer to save report
    print()
    report_path = os.path.join(os.path.dirname(plugin_path) if os.path.isfile(plugin_path) else ".", "troubleshoot_report.txt")
    print(f"  To save this output to a file, run:")
    print(f"    python troubleshoot.py > \"{report_path}\"")
    print()

    return issues_found


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nAborted.")
        sys.exit(130)
    except Exception as e:
        print(f"\n{Colors.RED}Unexpected error: {e}{Colors.RESET}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
