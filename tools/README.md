# PacketCircle Tools

Diagnostic and troubleshooting utilities for the PacketCircle Wireshark plugin.

## troubleshoot.bat — Quick Launch (Recommended)

Double-click or run from a command prompt — no execution policy changes needed:

```cmd
troubleshoot.bat
```

The `.bat` wrapper launches `troubleshoot.ps1` with a temporary `-ExecutionPolicy Bypass` for the current process only. It does **not** modify your system execution policy.

## troubleshoot.ps1 — Windows Dependency Checker (PowerShell)

Diagnoses DLL dependency and installation issues when the plugin fails to load on Windows 10/11. No extra software required — runs natively on any Windows 10/11 machine.

**Requirements:** PowerShell 5.1+ (built into Windows 10/11)

### Usage

**Preferred** — use the batch wrapper (avoids execution policy issues):
```cmd
troubleshoot.bat
```

**Alternative** — run the PowerShell script directly:
```powershell
.\troubleshoot.ps1
.\troubleshoot.ps1 -DllPath "C:\path\to\packetcircle.dll"
.\troubleshoot.ps1 | Tee-Object -FilePath report.txt
```

> If you run `troubleshoot.ps1` directly and see an execution policy error, either use `troubleshoot.bat` or run:
> `Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned`

### What it checks

| # | Check | Description |
|---|-------|-------------|
| 1 | System Info | Windows version, PowerShell version, admin status |
| 2 | Plugin DLL | PE header parsing — architecture, linker version, OS targeting, build timestamp |
| 3 | Wireshark | Installation path, version, architecture match, bundled DLLs |
| 4 | Plugin Directory | Scans existing plugin dirs, verifies `4-6` vs `4.6` path format |
| 5 | VC++ Runtime | Registry check for redistributable, CRT DLL versions (System32 + Wireshark) |
| 6 | Dependencies | Resolves all imported DLLs and verifies every imported function exists |
| 7 | DLL Load Test | Three-stage: data-file load, import-resolution, full Wireshark-context load |
| 8 | Plugin Loading | Queries `tshark -G plugins` to check if Wireshark recognizes the plugin |
| 9 | Security | Internet download block (Zone.Identifier), antivirus hints, config checks |

## troubleshoot.py — Windows Dependency Checker (Python)

Same diagnostics as the PowerShell version, for users who prefer Python.

**Requirements:** Python 3.6+ (standard library only — no pip packages needed)

```cmd
python troubleshoot.py
python troubleshoot.py C:\path\to\packetcircle.dll
```
