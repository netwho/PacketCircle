# PacketCircle — Troubleshooting Guide

---

## Quick Checklist

Before diving into specific issues, verify these basics:

1. **Wireshark version matches the plugin binary** — the most common cause of all load failures
2. **Plugin is in the correct directory** — check Help → About Wireshark → Folders → **Personal Plugins**
3. **Wireshark was restarted** after installing
4. **File permissions** are correct (`chmod 644 packetcircle.so` on Linux/macOS)

---

## Plugin Does Not Appear in Tools Menu

### Check 1 — Correct directory

Verify the plugin is in the directory Wireshark expects. Open Wireshark → **Help → About Wireshark → Folders → Personal Plugins** and confirm the file is there.

| Platform | Expected path |
|---|---|
| macOS (4.6.x) | `~/.local/lib/wireshark/plugins/4-6/epan/packetcircle.so` |
| Linux (4.6.x) | `~/.local/lib/wireshark/plugins/4.6/epan/packetcircle.so` |
| Linux (4.4.x) | `~/.local/lib/wireshark/plugins/4.4/epan/packetcircle.so` |
| Linux (4.2.x) | `~/.local/lib/wireshark/plugins/4.2/epan/packetcircle.so` |
| Windows (4.6.x) | `%APPDATA%\Wireshark\plugins\4.6\epan\packetcircle.dll` |

> **macOS uses dashes (`4-6`), Linux uses dots (`4.6`).** If you installed to the wrong format, move the file.

### Check 2 — Wipe stale installs

```bash
# Find all instances of the plugin (Linux/macOS)
ls -la ~/.local/lib/wireshark/plugins/*/epan/packetcircle.so 2>/dev/null

# Remove stale copies in wrong version directories
rm ~/.local/lib/wireshark/plugins/4-6/epan/packetcircle.so  # wrong format on Linux
```

### Check 3 — Permissions

```bash
chmod 644 ~/.local/lib/wireshark/plugins/4.6/epan/packetcircle.so
```

### Check 4 — Debug log

```bash
# Linux / macOS
wireshark -o log.level:debug 2>&1 | grep -i packetcircle
```

```cmd
# Windows — save debug log to file
"C:\Program Files\Wireshark\Wireshark.exe" -o log.level:debug 2> debug.txt
findstr /i packetcircle debug.txt
```

---

## `dlopen` / Library Not Loaded / Symbol Not Found

This is the most common error after installation. It means **the plugin binary does not match your Wireshark version**.

**Example errors:**
```
Library not loaded: @rpath/libwireshark.19.dylib   ← installed 4.6 binary, have 4.4.x or earlier
Library not loaded: @rpath/libwireshark.18.dylib   ← installed 4.4 binary, have 4.6.x
Symbol not found: _some_function_name              ← ABI mismatch between plugin and Wireshark
```

**Fix:** Re-run the installer — it auto-detects your Wireshark version and installs the correct binary. On Linux, four binaries are included (ws40/ws42/ws44/ws46); the installer picks the right one.

---

## Windows: Plugin Not Loading

### Step 1 — Unblock the DLL

If downloaded from GitHub, Windows may silently block the file.

- Right-click `packetcircle.dll` → **Properties** → check **Unblock** → Apply

Or in PowerShell:
```powershell
Unblock-File "$env:APPDATA\Wireshark\plugins\4.6\epan\packetcircle.dll"
```

The Windows installer does this automatically via `Unblock-File`.

### Step 2 — Install the VC++ 2022 Runtime

Download and install: [VC++ 2022 Redistributable (x64)](https://aka.ms/vs/17/release/vc_redist.x64.exe)

The Windows installer checks for this and reports whether it is present before installing.

### Step 3 — Run the automated diagnostics

A troubleshooting script is included in the Windows installer directory:

```cmd
cd installer\windows-x86_64
troubleshoot.bat
```

This checks DLL dependencies, verifies the plugin directory, tests DLL loading, detects internet-download blocks, and reports exactly what is wrong. No extra software required — runs natively on Windows 10/11.

You can also run the PowerShell script directly:
```powershell
.\troubleshoot.ps1
```

### Windows 10 vs Windows 11

The plugin is verified on Windows 11. On Windows 10, the three steps above resolve most issues. If problems persist, the debug log (see above) will identify the failing DLL.

---

## macOS: Crash Report After Closing Wireshark

**Fixed in v0.5.3.** Earlier releases (v0.5.2 and below) could trigger a macOS crash report for Wireshark on exit. The root cause was a sequencing issue in Wireshark's own shutdown: `epan_cleanup()` called `g_module_close()` on the plugin DSO — unmapping its code — before `QApplication::~QApplication()` had finished cleaning up Qt's accessibility cache. The cache then tried to call into unmapped vtable memory, producing a `SIGSEGV` in `QAccessibleCache::~QAccessibleCache()`.

**Fix (v0.5.3):** The plugin now calls `dlopen(..., RTLD_NODELETE)` on itself at registration time, which prevents the dynamic linker from unmapping the DSO when `dlclose()` is called. The mapping remains valid through the full Qt teardown and is reclaimed by the OS at process exit.

No workaround is needed with v0.5.3 or later. If you are still on an older release, upgrading resolves the issue entirely.

---

## Linux: GLIBC_2.38 Error

**Symptom:** Plugin fails to load with an error mentioning `GLIBC_2.38`, `__isoc23_sscanf`, or `__isoc23_strtoul` on Ubuntu 22.04, Debian 12, or similar older distributions.

**Cause:** Binaries built on Ubuntu 24.04 (glibc 2.39) referenced C23 glibc variants. This was fixed in v0.4.4 with a `glibc_compat.c` shim.

**Fix:** Install v.0.4.4 or later (current release is v.0.5.2).

---

## Linux: Plugin Not Found After Manual Install

**Common mistake:** Using `4-6` (dashes) on Linux. Linux Wireshark expects dots.

```bash
# Wrong:
~/.local/lib/wireshark/plugins/4-6/epan/packetcircle.so

# Correct:
~/.local/lib/wireshark/plugins/4.6/epan/packetcircle.so
```

Move the file if needed:
```bash
mkdir -p ~/.local/lib/wireshark/plugins/4.6/epan/
mv ~/.local/lib/wireshark/plugins/4-6/epan/packetcircle.so \
   ~/.local/lib/wireshark/plugins/4.6/epan/
```

---

## Linux: DBus Warnings at Startup

Messages like:
```
Session DBus not running
```

These are harmless Qt warnings. They do not prevent the plugin from loading or functioning. Ignore them.

---

## Plugin Loads but Crashes

1. Confirm the binary architecture matches your system: `file ~/.local/lib/wireshark/plugins/4.6/epan/packetcircle.so`
2. Confirm your Wireshark version is supported (4.6.x for macOS/Windows; 4.0–4.6 for Linux)
3. Re-run the installer to reinstall a clean copy
4. Check the Wireshark debug log for error details

---

## PDF Export Issues

- Ensure a capture is loaded and PacketCircle has at least one pair visible before clicking PDF
- If the PDF is blank, check that the circle view is active (not table view) when exporting
- Verify write permissions on the export destination path

---

## Protocol Info Dialog Shows "No Data"

This is normal if:
- The capture does not contain traffic on the trigger port for that dialog (e.g. no TLS traffic for a TLS info dialog)
- A Wireshark display filter is active that excludes the relevant packets
- The capture started mid-session (e.g. mid-TLS handshake — certificate details will be missing)

All protocol info dialogs filter data to the **selected pair only** — they do not scan the entire capture.

---

## Getting More Help

- **Check Wireshark debug log** — always the most informative source of load errors
- **Verify with the installer** — re-running it shows the detected Wireshark version, binary availability, and existing install in a clear prerequisites summary
- **GitHub Issues** — [github.com/netwho/PacketCircle/issues](https://github.com/netwho/PacketCircle/issues) — include your OS, Wireshark version, and the relevant lines from the debug log
