# PacketCircle — Installation Guide

Everything you need to install, update, or remove PacketCircle on any supported platform.

---

## Getting the Files

### No git? Download the zip (macOS and Windows)

**[⬇ Download installer.zip](https://github.com/netwho/PacketCircle/raw/main/installer.zip)** — contains macOS and Windows installers only

> **Linux users:** the zip does not include Linux binaries (too large to distribute this way). Use git clone below — it is the preferred path for Linux.

1. Click the link above and save `installer.zip`
2. Unzip it — you get an `installer/` folder containing macOS and Windows installers for both plugin versions
3. Jump to the section for your platform below and run the installer from there

> The zip includes installer scripts, macOS and Windows binaries, and troubleshooting tools. No account, no git needed to download it.

### git users (all platforms — required for Linux)

```bash
git clone https://github.com/netwho/PacketCircle.git
cd PacketCircle
```

The `installer/` directory is included in the repository at the root level, with all platforms and both plugin versions.

---

## Prerequisites

| Platform | Wireshark | Additional |
|---|---|---|
| **macOS** 13.0+ (Ventura) | 4.6.x | None — Universal Binary (Intel + Apple Silicon) |
| **Windows** 10/11 x86_64 | 4.6.x | VC++ 2022 Redistributable x64 ¹ |
| **Linux** x86_64 | 4.0.x / 4.2.x / 4.4.x / 4.6.x | Qt6 runtime (4.0.x only) ² |

> ¹ The Windows installer checks for the VC++ runtime and provides the download link if missing.
> ² The Linux installer detects missing Qt6 and offers to install `libqt6widgets6` automatically.

---

## Which Version to Install?

The installer offers **v.0.5.3** (latest) and **v.0.4.7** (last v0.4.x). **Always choose v.0.5.3** unless you have a specific reason to stay on v.0.4.7.

| Version | Highlights |
|---|---|
| **v.0.5.3** (recommended) | Star-default graph layout, graph Edge/Node/Layout settings persisted, improved protocol legend, macOS exit crash fix |
| **v.0.4.7** (legacy) | 20+ protocol info dialogs, ntopng & Malcolm/Arkime integration, settings menu, TCP/UDP transport details, Connection Details popup & context menu |

You can switch versions at any time by re-running the installer.

---

## macOS (Intel & Apple Silicon) — Wireshark 4.6.x

### Installer (recommended)

```bash
git clone https://github.com/netwho/PacketCircle.git
cd PacketCircle/installer/macos-universal
chmod +x install.sh
./install.sh
```

The installer:
- Detects your Wireshark version and the correct plugin directory format (`4-6` vs `4.6`)
- Shows any currently installed version
- Lets you choose install location: **personal** (`~/.local/lib/wireshark/…`) or **app bundle** (`/Applications/Wireshark.app/…`)
- Offers uninstall

### Manual Install

Find your exact plugin path in Wireshark under **Help → About Wireshark → Folders → Personal Plugins**.

```bash
# Create the plugin directory (macOS uses dashes: 4-6)
mkdir -p ~/.local/lib/wireshark/plugins/4-6/epan/

# Install v.0.5.3 (latest):
cp installer/macos-universal/v.0.5.3/packetcircle.so \
   ~/.local/lib/wireshark/plugins/4-6/epan/packetcircle.so

# Or install v.0.4.7 (legacy):
cp installer/macos-universal/v.0.4.7/packetcircle.so \
   ~/.local/lib/wireshark/plugins/4-6/epan/packetcircle.so
```

Restart Wireshark after installing.

---

## Linux (x86_64) — Wireshark 4.0.x / 4.2.x / 4.4.x / 4.6.x

### Installer (recommended)

```bash
git clone https://github.com/netwho/PacketCircle.git
cd PacketCircle/installer/linux-x86_64
chmod +x install.sh
./install.sh
```

The installer:
- Checks all plugin binaries are present and reports their sizes
- Detects Wireshark version via `tshark`, `wireshark`, `dpkg`, `rpm`, or `pacman`
- Searches for the correct plugin directory (dots vs dashes)
- Checks Qt6 runtime availability and offers to install it if missing
- Pauses for you to review the prerequisites summary before proceeding
- Recommends v.0.5.3 and warns if you select v.0.4.7

> **Note:** Run with `bash install.sh` or `chmod +x install.sh && ./install.sh`. Do not use `sh install.sh` — the script requires bash.

### Qt6 on Wireshark 4.0.x

Wireshark 4.0.x does not bundle Qt6. If Qt6 is not on your system the installer detects this and offers:

```bash
sudo apt-get install -y libqt6widgets6    # Debian / Ubuntu
sudo dnf install qt6-qtbase              # Fedora / RHEL
sudo pacman -S qt6-base                  # Arch
sudo zypper install libQt6Widgets6       # openSUSE
```

### Manual Install

```bash
# Pick the binary matching your Wireshark version:
#   packetcircle-ws40.so  →  Wireshark 4.0.x
#   packetcircle-ws42.so  →  Wireshark 4.2.x
#   packetcircle-ws44.so  →  Wireshark 4.4.x
#   packetcircle-ws46.so  →  Wireshark 4.6.x
# (v.0.4.7 has ws40/ws42/ws44/ws46; v.0.5.3 has the same set)

# Example: Wireshark 4.6.x, v.0.5.3:
mkdir -p ~/.local/lib/wireshark/plugins/4.6/epan/
cp installer/linux-x86_64/v.0.5.3/packetcircle-ws46.so \
   ~/.local/lib/wireshark/plugins/4.6/epan/packetcircle.so

# Example: Wireshark 4.2.x, v.0.5.3:
mkdir -p ~/.local/lib/wireshark/plugins/4.2/epan/
cp installer/linux-x86_64/v.0.5.3/packetcircle-ws42.so \
   ~/.local/lib/wireshark/plugins/4.2/epan/packetcircle.so
```

### Supported Wireshark × Plugin Version Matrix (Linux)

| Wireshark | v.0.5.3 binary | v.0.4.7 binary |
|---|---|---|
| 4.0.x | `packetcircle-ws40.so` | `packetcircle-ws40.so` |
| 4.2.x | `packetcircle-ws42.so` | `packetcircle-ws42.so` |
| 4.4.x | `packetcircle-ws44.so` | `packetcircle-ws44.so` |
| 4.6.x | `packetcircle-ws46.so` | `packetcircle-ws46.so` |

> **Why separate binaries?** Wireshark uses a versioned plugin ABI per minor release series. A binary built for 4.6.x will not load in 4.4.x, and vice versa.

---

## Windows (x86_64) — Wireshark 4.6.x

### Installer (recommended)

**Double-click `install.bat`** or run from a Command Prompt:

```cmd
cd installer\windows-x86_64
install.bat
```

The `.bat` file launches the PowerShell installer with `-ExecutionPolicy Bypass` for the current process only — it does **not** change your system policy.

The installer:
- Reports OS version (Win10 / Win11), architecture, and VC++ runtime status upfront
- Searches all standard Wireshark install locations and shows each path checked
- Detects your installed Wireshark version from EXE metadata or `tshark`
- Shows which plugin binaries are present (with file sizes)
- Detects any existing PacketCircle installation and its version
- Prints a prerequisites summary before prompting
- Recommends v.0.5.3; warns if you choose v.0.4.7

<details>
<summary>Run the PowerShell script directly</summary>

```powershell
cd installer\windows-x86_64
.\install.ps1
```

If you see an execution policy error, use `install.bat` instead, or run:
```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```
</details>

### Manual Install

```powershell
# Check your exact path: Help → About Wireshark → Folders → Personal Plugins

# Install v.0.5.3 (latest):
Copy-Item installer\windows-x86_64\v.0.5.3\packetcircle.dll `
          "$env:APPDATA\Wireshark\plugins\4.6\epan\"

# Or install v.0.4.7 (legacy):
Copy-Item installer\windows-x86_64\v.0.4.7\packetcircle.dll `
          "$env:APPDATA\Wireshark\plugins\4.6\epan\"
```

### Windows 10 Notes

- **Unblock the DLL**: If downloaded from GitHub, right-click `packetcircle.dll` → Properties → **Unblock** → Apply. The installer does this automatically via `Unblock-File`.
- **VC++ 2022 Runtime**: Required. Download: [vc_redist.x64.exe](https://aka.ms/vs/17/release/vc_redist.x64.exe)

---

## Uninstalling

Re-run the installer and choose **u) Uninstall** at the menu, or remove the file manually:

```bash
# macOS
rm ~/.local/lib/wireshark/plugins/4-6/epan/packetcircle.so

# Linux (all version dirs)
rm ~/.local/lib/wireshark/plugins/*/epan/packetcircle.so
```

```powershell
# Windows
Remove-Item "$env:APPDATA\Wireshark\plugins\4.6\epan\packetcircle.dll"
```

Restart Wireshark after uninstalling.

---

## Building from Source

For unsupported platforms or Wireshark versions, or to develop PacketCircle itself.

**Prerequisites:**
- Wireshark source code matching your installed version
- CMake 3.10+
- Qt6 (Core, Widgets, Gui) — must match the Qt version bundled by Wireshark exactly
- GLib 2.54+
- C/C++ compiler (Clang recommended on macOS)

> **Critical:** Do not use Homebrew's `qt@6` — even a minor version mismatch causes ABI errors at runtime. Use `aqtinstall` to get the exact matching version. See `tools/build-tools/BUILD-MACOS-HOST.md`.

```bash
# Place src/ contents into the Wireshark plugin directory
cp -r src/* /path/to/wireshark-source/plugins/epan/packetcircle/

cd /path/to/wireshark-source
mkdir build && cd build
cmake -DCUSTOM_PLUGIN_SRC_DIR=plugins/epan/packetcircle ..
make packetcircle
```

Full build guides: `tools/build-tools/BUILD-MACOS-HOST.md`, `BUILD-LINUX-LOCAL.md`, `BUILD-WINDOWS-HOST.md`.

---

*→ Stuck? See [TROUBLESHOOTING.md](TROUBLESHOOTING.md)*
