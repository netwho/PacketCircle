# PacketCircle Quick Start Guide

Get up and running with PacketCircle in under 5 minutes.

> **Requirement**: Pre-built Linux binaries support **Wireshark 4.0.x, 4.2.x, 4.4.x, and 4.6.x**. The unified installer auto-detects your version. macOS and Windows target **Wireshark 4.6.x**. For other versions, build from source (see `src/BUILD.md`).

## Installation

> **v.0.4.6 or v.0.3.2?**
> The installer lets you choose between **v.0.4.6** (latest — protocol info dialogs, ntopng & Malcolm/Arkime integrations, settings menu, TCP/UDP transport details) and **v.0.3.2** (legacy stable).
> You can switch versions at any time by re-running the installer.

### macOS (Intel & Apple Silicon) — Wireshark 4.6.x

1. **Download or clone the repository:**
   ```bash
   git clone https://github.com/netwho/PacketCircle.git
   cd PacketCircle
   ```

2. **Run the installer:**
   ```bash
   cd installer/macos-universal
   chmod +x install.sh
   ./install.sh
   ```

3. **Restart Wireshark** if it's already running.

### Linux (x86_64) — Wireshark 4.0.x / 4.2.x / 4.4.x / 4.6.x

1. **Download or clone the repository:**
   ```bash
   git clone https://github.com/netwho/PacketCircle.git
   cd PacketCircle
   ```

2. **Run the unified installer:**
   ```bash
   cd installer/linux-x86_64
   chmod +x install.sh
   ./install.sh
   ```

   The installer automatically detects your Wireshark version and installs the matching binary.

   > **Wireshark 4.0.x**: requires Qt6 on the host system. The installer checks for this and provides the install command if needed:
   > ```bash
   > sudo apt install libqt6widgets6    # Debian/Ubuntu
   > ```

3. **Restart Wireshark** if it's already running.

### Windows (x86_64) — Wireshark 4.6.x

1. **Download or clone the repository** (or copy the `installer/windows-x86_64` folder to your PC).

2. **Run the installer** — double-click `install.bat` or from a Command Prompt:
   ```cmd
   cd installer\windows-x86_64
   install.bat
   ```

   The `.bat` wrapper launches the PowerShell installer with a temporary `-ExecutionPolicy Bypass` for the current process only — it does **not** change your system policy.

3. **Restart Wireshark** if it's already running.

### Manual Installation

Copy the plugin file directly into your Wireshark personal plugins folder — no installer needed. To find the exact path on your system open Wireshark → **Help → About Wireshark → Folders → Personal Plugins**.

Replace `v.0.4.6` with `v.0.3.2` in any path below to install the legacy version instead.

**macOS** (Wireshark 4.6.x, uses dashes: `4-6`):
```bash
mkdir -p ~/.local/lib/wireshark/plugins/4-6/epan/
cp installer/macos-universal/v.0.4.6/packetcircle.so ~/.local/lib/wireshark/plugins/4-6/epan/
```

**Linux** (uses dots — pick the binary matching your Wireshark version):
```bash
# Wireshark 4.0.x
mkdir -p ~/.local/lib/wireshark/plugins/4.0/epan/
cp installer/linux-x86_64/bin/v.0.4.6/packetcircle-ws40.so ~/.local/lib/wireshark/plugins/4.0/epan/packetcircle.so

# Wireshark 4.2.x
mkdir -p ~/.local/lib/wireshark/plugins/4.2/epan/
cp installer/linux-x86_64/bin/v.0.4.6/packetcircle-ws42.so ~/.local/lib/wireshark/plugins/4.2/epan/packetcircle.so

# Wireshark 4.4.x (e.g. Debian 13 Trixie)
mkdir -p ~/.local/lib/wireshark/plugins/4.4/epan/
cp installer/linux-x86_64/bin/v.0.4.6/packetcircle-ws44.so ~/.local/lib/wireshark/plugins/4.4/epan/packetcircle.so

# Wireshark 4.6.x
mkdir -p ~/.local/lib/wireshark/plugins/4.6/epan/
cp installer/linux-x86_64/bin/v.0.4.6/packetcircle-ws46.so ~/.local/lib/wireshark/plugins/4.6/epan/packetcircle.so
```

**Windows** (PowerShell):
```powershell
Copy-Item installer\windows-x86_64\v.0.4.6\packetcircle.dll "$env:APPDATA\Wireshark\plugins\4.6\epan\"
```

## First Use

### Step 1: Open a Capture

Open Wireshark and load a PCAP/PCAPNG file, or start a live capture.

### Step 2: Launch PacketCircle

Go to **Tools -> PacketCircle** in the menu bar. The PacketCircle window will open showing the circle visualization.

### Step 3: Explore the Visualization

- **Nodes** around the circle represent network endpoints (IP or MAC addresses)
- **Lines** between nodes represent communication pairs
- **Line color** indicates the highest protocol observed
- **Line thickness** represents traffic volume (packets or bytes)
- **Dotted lines** with alternating colors indicate mixed TCP+UDP communication

### Step 4: Interact

| Action | Result |
|--------|--------|
| **Hover** over a node | See IP address, packet counts, destination ports, and service names |
| **Check/uncheck** pairs in the list | Select which pairs are visible on the circle |
| **Click a line** in the circle | Open the connection popup with per-port details |
| **Right-click** a connection row | Apply a display filter, follow TCP stream, open protocol info dialog |
| **Click "Filter"** | Apply a Wireshark display filter matching the selected pairs |
| **Click "Clear Filter"** | Remove the display filter and show all traffic |
| **Use protocol checkboxes** | Filter the view to show only specific protocols |
| **Click "PDF"** | Export a one-page report to PDF |

### Step 5: Adjust the View

- **Top 10 / 25 / 50** - Limit the number of displayed conversations
- **Packets / Bytes** - Change the metric used for line weight
- **Circle / Table** - Switch between visualization and tabular view
- **MAC / IP** - Toggle between MAC address and IP address mode
- **⚙ Settings** - Configure ntopng, Malcolm/Arkime, CA certificates, and reset defaults
- **Drag the splitter** between the circle and the pair list to resize panels

## Tips

- Use **Select None** followed by checking individual pairs to isolate specific conversations
- The **Search** box accepts IP addresses, CIDR ranges, port queries (`TCP 443`, `UDP 53`), protocol categories (`TCP`, `UDP`, `Infrastructure`), and protocol keywords (`TLS`, `HTTP`, `SMB`, `Kerberos`, `SMTP`, `LDAP`, `SNMP`, `SSH`, `FTP`, `Telnet`, `NBNS`, `VoIP`, …)
- **Protocol checkboxes** in the legend let you filter by protocol type (e.g., show only HTTP traffic)
- When a pair uses both TCP and UDP, filtering to a single protocol changes the line from dotted to solid
- The **PDF export** generates print-optimized output with white background, high-contrast labels, and readable fonts
- **Right-click any connection** to open deep protocol info dialogs (TLS, HTTP, SMB, Kerberos, DNS, DHCP, SSH, FTP, and more)

## Keyboard Shortcuts

PacketCircle integrates with Wireshark's standard shortcuts. The plugin window can be resized and moved freely.

## Uninstalling

Re-run the installer and choose **u) Uninstall**, or remove the plugin file manually:

```bash
# macOS
rm ~/.local/lib/wireshark/plugins/4-6/epan/packetcircle.so

# Linux (remove from whichever version directory was used)
rm ~/.local/lib/wireshark/plugins/*/epan/packetcircle.so
```

```powershell
# Windows
Remove-Item "$env:APPDATA\Wireshark\plugins\4.6\epan\packetcircle.dll"
```

Then restart Wireshark.

---

*AI-Assisted: yes (Claude) — documentation*
