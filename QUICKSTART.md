# PacketCircle Quick Start Guide

Get up and running with PacketCircle in under 5 minutes.

> **Requirement**: Pre-built binaries are available for **Wireshark 4.4.x** and **4.6.x**. Use the matching installer for your version. For other versions (4.2, 4.0), build from source (see `src/BUILD.md`).

## Installation

### macOS (Recommended)

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

### Linux — Wireshark 4.4.x (e.g. Debian 13 Trixie)

1. **Download or clone the repository:**
   ```bash
   git clone https://github.com/netwho/PacketCircle.git
   cd PacketCircle
   ```

2. **Run the 4.4.x installer:**
   ```bash
   cd installer/linux-x86_64-ws44
   chmod +x install.sh
   ./install.sh
   ```

3. **Restart Wireshark** if it's already running.

### Manual Installation

First verify your Wireshark version: Help -> About Wireshark.

Copy the plugin binary to your personal Wireshark plugin directory:

**macOS** (Wireshark 4.6.x, uses dashes: `4-6`):
```bash
mkdir -p ~/.local/lib/wireshark/plugins/4-6/epan/
cp installer/macos-universal/packetcircle.so ~/.local/lib/wireshark/plugins/4-6/epan/
```

**Linux** (Wireshark 4.6.x, uses dots: `4.6`):
```bash
mkdir -p ~/.local/lib/wireshark/plugins/4.6/epan/
cp installer/linux-x86_64/packetcircle.so ~/.local/lib/wireshark/plugins/4.6/epan/
```

**Linux** (Wireshark 4.4.x, uses dots: `4.4`):
```bash
mkdir -p ~/.local/lib/wireshark/plugins/4.4/epan/
cp installer/linux-x86_64-ws44/packetcircle.so ~/.local/lib/wireshark/plugins/4.4/epan/
```

> **Tip**: Find your exact plugin directory in Wireshark under Help -> About Wireshark -> Folders -> Personal Plugins.

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
| **Click "Filter"** | Apply a Wireshark display filter matching the selected pairs |
| **Click "Clear Filter"** | Remove the display filter and show all traffic |
| **Use protocol checkboxes** | Filter the view to show only specific protocols |
| **Click "PDF"** | Export a one-page report to PDF |

### Step 5: Adjust the View

- **Top 10 / 25 / 50** - Limit the number of displayed conversations
- **Packets / Bytes** - Change the metric used for line weight
- **Circle / Table** - Switch between visualization and tabular view
- **MAC / IP** - Toggle between MAC address and IP address mode
- **Drag the splitter** between the circle and the pair list to resize panels

## Tips

- Use **Select None** followed by checking individual pairs to isolate specific conversations
- The **Search** box above the pair list lets you quickly find specific IP addresses
- **Protocol checkboxes** in the legend let you filter by protocol type (e.g., show only HTTP traffic)
- When a pair uses both TCP and UDP, filtering to a single protocol changes the line from dotted to solid
- The **PDF export** generates print-optimized output with white background, high-contrast labels, and readable fonts

## Keyboard Shortcuts

PacketCircle integrates with Wireshark's standard shortcuts. The plugin window can be resized and moved freely.

## Uninstalling

Remove the plugin file:

```bash
# macOS (Wireshark 4.6.x)
rm ~/.local/lib/wireshark/plugins/4-6/epan/packetcircle.so
# Linux (Wireshark 4.6.x)
rm ~/.local/lib/wireshark/plugins/4.6/epan/packetcircle.so
# Linux (Wireshark 4.4.x)
rm ~/.local/lib/wireshark/plugins/4.4/epan/packetcircle.so
```

Then restart Wireshark.
