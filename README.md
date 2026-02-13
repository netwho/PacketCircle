# PacketCircle

[![Version](https://img.shields.io/badge/version-0.2.2-blue.svg)](CHANGELOG.md)
[![Status](https://img.shields.io/badge/status-public%20beta-orange.svg)](CHANGELOG.md)
[![License: GPL v2](https://img.shields.io/badge/License-GPL%20v2-blue.svg)](LICENSE)
[![Wireshark](https://img.shields.io/badge/Wireshark-4.4.x%20%7C%204.6.x-1679A7.svg)](https://www.wireshark.org/)
[![C++/Qt6](https://img.shields.io/badge/C%2B%2B%2FQt6-Native-41CD52.svg)](https://www.qt.io/)
[![macOS](https://img.shields.io/badge/macOS-Universal%20Binary-000000.svg?logo=apple)](installer/macos-universal/)
[![Linux](https://img.shields.io/badge/Linux-x86__64-FCC624.svg?logo=linux&logoColor=black)](installer/linux-x86_64/)

A native Wireshark plugin that visualizes network communication pairs in an interactive circle diagram with protocol color coding, traffic volume indicators, and PDF report export.

> **Beta Status**: This is version 0.2.2, a public beta release. While fully functional, the software is under active development. Please report any issues you encounter.

## Features

- **Circle Visualization** - Interactive circular graph showing communication relationships between network endpoints
- **Protocol Color Coding** - Lines colored by the highest protocol observed (HTTP, HTTPS, SMB, DNS, MSSQL, SSH, FTP, etc.)
- **Line Weight** - Proportional to packet/byte volume for at-a-glance traffic assessment
- **Mixed Protocol Indicators** - Dotted lines with alternating colors for connections using both TCP and UDP
- **Node Tooltips** - Hover over nodes to see destination ports, service names, and packet counts
- **Directional Filtering** - Select individual communication pairs to apply precise unidirectional Wireshark display filters
- **Protocol Filtering** - Filter the visualization by specific protocols using interactive checkboxes
- **PDF Report Export** - Generate a one-page PDF report with the circle visualization, IP pair table, and summary text
- **Multiple Views** - Toggle between circle view and table view
- **Conversation Limits** - Limit display to top 10, 25, or 50 conversations
- **Live Capture Support** - Works with both loaded PCAP files and live captures
- **Universal Binary** - Single binary runs natively on both Intel and Apple Silicon Macs

## Screenshots

### PacketCircle Visualization

Access the plugin from the Wireshark menu:
```
Tools -> PacketCircle
```

![PacketCircle Screenshot](screenshots/packetcircle-main.png)

*Interactive circle visualization showing network communication pairs with protocol color coding*

![PacketCircle Screenshot](screenshots/packetcircle-filter.png)

*Setting a filter based on the visualization*


## Quick Start

> **Important**: Pre-built binaries are available for **Wireshark 4.4.x** and **4.6.x**. The installer will check your version and warn you if it's incompatible. See [Supported Wireshark Versions](#supported-wireshark-versions) for details.

### Installation

#### macOS (Intel & Apple Silicon) — Wireshark 4.6.x
```bash
git clone https://github.com/netwho/PacketCircle.git
cd PacketCircle/installer/macos-universal
chmod +x install.sh
./install.sh
```

#### Linux (x86_64) — Wireshark 4.6.x
```bash
git clone https://github.com/netwho/PacketCircle.git
cd PacketCircle/installer/linux-x86_64
chmod +x install.sh
./install.sh
```

#### Linux (x86_64) — Wireshark 4.4.x (e.g. Debian 13 Trixie)
```bash
git clone https://github.com/netwho/PacketCircle.git
cd PacketCircle/installer/linux-x86_64-ws44
chmod +x install.sh
./install.sh
```

#### Manual Install

> **Important**: macOS uses **dashes** (`4-6`), Linux uses **dots** (`4.6` or `4.4`) in the plugin directory name.

```bash
# macOS (Wireshark 4.6.x)
mkdir -p ~/.local/lib/wireshark/plugins/4-6/epan/
cp installer/macos-universal/packetcircle.so ~/.local/lib/wireshark/plugins/4-6/epan/

# Linux (Wireshark 4.6.x)
mkdir -p ~/.local/lib/wireshark/plugins/4.6/epan/
cp installer/linux-x86_64/packetcircle.so ~/.local/lib/wireshark/plugins/4.6/epan/

# Linux (Wireshark 4.4.x)
mkdir -p ~/.local/lib/wireshark/plugins/4.4/epan/
cp installer/linux-x86_64-ws44/packetcircle.so ~/.local/lib/wireshark/plugins/4.4/epan/
```

> **Tip**: Check your exact plugin path in Wireshark under Help -> About Wireshark -> Folders -> Personal Plugins.

### Usage

1. **Load a capture file** in Wireshark (or start a live capture)
2. **Open PacketCircle**: Tools -> PacketCircle
3. **Explore**: Hover over nodes for details, click pairs to filter
4. **Export**: Click "PDF" to generate a report

See [QUICKSTART.md](QUICKSTART.md) for a detailed guide.

## Protocol Color Mapping

The plugin colors connections by their transport/network layer protocol:

| Protocol | Color |
|----------|-------|
| TCP | Green |
| UDP | Orange |
| ARP | Sky Blue |
| ICMP | Turquoise |
| ICMPv6 | Pink |
| OSPF, RIP, EIGRP | Peach/Moccasin |
| BGP, IGMP | Light Pink |
| PIM | Lavender |
| VRRP | Khaki |
| HSRP | Plum |
| SCTP | Lemon |
| DCCP | Pink |
| IPv4/IPv6 | Light Gray |
| Ethernet | Silver |
| Unknown | Gray |

Protocols not in the built-in palette are assigned a consistent auto-generated color based on their name.

## Controls

| Control | Description |
|---------|-------------|
| **Top 10 / 25 / 50** | Limit visible conversations |
| **Packets / Bytes** | Switch metric for line weight |
| **Circle / Table** | Toggle visualization mode |
| **MAC / IP** | Switch between MAC and IP address pairs |
| **Select All / None** | Bulk pair selection |
| **Filter** | Apply Wireshark display filter for selected pairs |
| **Clear Filter** | Reset Wireshark display filter and show all connections |
| **PDF** | Export a one-page PDF report |
| **Protocol checkboxes** | Filter by specific protocols (TCP, UDP, HTTP, DNS, etc.) |
| **Line Thickness** | Toggle proportional line weight on/off |
| **Search** | Filter the IP pair list by address |

## PDF Report

The PDF export generates a professional one-page report including:

- **Header** with PacketCircle logo and report title
- **Summary text** describing the capture (packet count, unique hosts, time range)
- **Circle visualization** rendered with print-optimized colors (white background, high-contrast labels)
- **IP pair table** listing source, destination, packets, and bytes
- **Footer** with generation timestamp

## Architecture

```
src/
  circle_plugin.c/h      # Plugin entry point and Wireshark integration
  packet_analyzer.c/h    # Packet analysis engine, communication pair extraction
  circle_widget.c/h      # Qt widget for circle rendering, tooltips, PDF rendering
  ui_main_window.c/h     # Main window, controls, filter logic, PDF export
  ui_bridge.cpp/h        # C/C++ bridge for Wireshark plugin API
  plugin.c               # Plugin registration
  CMakeLists.txt         # Build configuration
  packetcircle.qrc       # Qt resource file (embedded assets)
```

## Building from Source

### Prerequisites

- Wireshark source code (matching your installed version, e.g., 4.6.3)
- CMake 3.10+
- Qt6 (Core, Widgets, Gui)
- GLib 2.54+
- C/C++ compiler (Clang recommended on macOS)

### Build Instructions

1. Place the `src/` contents into `plugins/epan/packetcircle/` within the Wireshark source tree
2. Configure and build:

```bash
cd wireshark-source
mkdir build && cd build
cmake -DCUSTOM_PLUGIN_SRC_DIR=plugins/epan/packetcircle ..
make packetcircle
```

3. The built plugin is at:
```
build/run/Wireshark.app/Contents/PlugIns/wireshark/4-6/epan/packetcircle.so
```

### Building a Universal Binary

To create a binary that works on both Intel and Apple Silicon Macs:

1. Build for arm64 (on Apple Silicon Mac with `/opt/homebrew` dependencies)
2. Install x86_64 Homebrew and dependencies at `/usr/local`
3. Build for x86_64 in a separate build directory
4. Merge with `lipo`:

```bash
lipo -create build-arm64/packetcircle.so build-x86_64/packetcircle.so -output packetcircle-universal.so
```

See [BUILD.md](src/BUILD.md) for detailed instructions.

## Supported Wireshark Versions

Pre-built binaries are available for two Wireshark release series:

| Wireshark Version | macOS (Universal) | Linux x86_64 | Installer Directory |
|---|---|---|---|
| **4.6.x** (4.6.0 – 4.6.x) | Supported | Supported | `installer/linux-x86_64/` |
| **4.4.x** (4.4.0 – 4.4.x) | — | Supported | `installer/linux-x86_64-ws44/` |
| 4.2.x | — | — | Build from source |
| 4.0.x | — | — | Build from source |

> **Why separate builds?** Wireshark uses a versioned plugin ABI (`MAJOR.MINOR`). Each minor release series (4.0, 4.2, 4.4, 4.6) has its own ABI. Pre-built plugins only load in the matching series. To use PacketCircle with a different Wireshark version, build from source against that version's source tree (see [Building from Source](#building-from-source)).
>
> **Debian 13 (Trixie)** ships Wireshark 4.4.x — use the `linux-x86_64-ws44` installer.

## Requirements

- **Wireshark** 4.4.x or 4.6.x (pre-built binaries) or 4.x (build from source)
- **macOS** 13.0 or later (Ventura+) — Universal Binary (Intel + Apple Silicon)
- **Linux** x86_64 — Ubuntu 24.04+, Debian 12+/13, Fedora 39+, or similar with Qt6
- No additional runtime dependencies beyond what Wireshark provides

## Documentation

- **[QUICKSTART.md](QUICKSTART.md)** - 5-minute getting started guide
- **[CHANGELOG.md](CHANGELOG.md)** - Version history
- **[LICENSE](LICENSE)** - GNU GPL v2

## Troubleshooting

### `dlopen` Error: Library not loaded / Symbol not found

This is the most common error and means **your Wireshark version doesn't match the plugin binary**.

**Example errors:**
- `Library not loaded: @rpath/libwireshark.19.dylib` — you are using the 4.6.x plugin with Wireshark 4.4.x (which ships `libwireshark.18`). Use the `linux-x86_64-ws44` installer instead.
- `Library not loaded: @rpath/libwireshark.18.dylib` — you are using the 4.4.x plugin with Wireshark 4.6.x. Use the `linux-x86_64` installer instead.
- `Symbol not found: _some_function_name` — similar ABI mismatch between your Wireshark and the plugin.

**Fix:** Use the matching installer for your Wireshark version, or build from source (see [Building from Source](#building-from-source)).

### Plugin Not Appearing in Tools Menu

**Check:**
1. Your Wireshark version matches the plugin binary (Help -> About Wireshark)
2. Plugin is in the correct directory (note: macOS uses dashes, Linux uses dots):
   - macOS (4.6.x): `~/.local/lib/wireshark/plugins/4-6/epan/`
   - Linux (4.6.x): `~/.local/lib/wireshark/plugins/4.6/epan/`
   - Linux (4.4.x): `~/.local/lib/wireshark/plugins/4.4/epan/`
3. File has correct permissions: `chmod 644 packetcircle.so`
4. Wireshark was restarted after installation
5. Verify the exact path: Help -> About Wireshark -> Folders -> Personal Plugins

**Fix:**
```bash
# Verify location (macOS, Wireshark 4.6.x)
ls -la ~/.local/lib/wireshark/plugins/4-6/epan/packetcircle.so

# Verify location (Linux, Wireshark 4.6.x)
ls -la ~/.local/lib/wireshark/plugins/4.6/epan/packetcircle.so

# Verify location (Linux, Wireshark 4.4.x — e.g. Debian 13)
ls -la ~/.local/lib/wireshark/plugins/4.4/epan/packetcircle.so

# Fix permissions
chmod 644 packetcircle.so
```

> **Common Linux issue**: If you installed to `4-6` (dashes) on Linux, move the file to `4.6` (dots). Linux Wireshark uses dots in the plugin version directory.

> **DBus warnings**: Messages like "Session DBus not running" are harmless Qt warnings and do not prevent the plugin from loading.

### Plugin Loads but Crashes

- Ensure you're using a compatible Wireshark version (4.4.x or 4.6.x for pre-built binaries)
- Check that the binary matches your architecture (`file packetcircle.so`)
- Try reinstalling from the universal binary

### PDF Export Issues

- Ensure a capture file is loaded before exporting
- Check that at least one communication pair exists in the visualization

## License

GNU General Public License v2 - see [LICENSE](LICENSE) file for details.

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.

## Acknowledgments

- Wireshark development team for the plugin framework and Qt integration
- Network analysis community for feedback and testing

## Support & Contact

- **Issues**: [GitHub Issues](https://github.com/netwho/PacketCircle/issues)
- **Documentation**: See docs in this repository

---

**Built with ❤️ for the network analysis community** — [github.com/netwho/PacketCircle](https://github.com/netwho/PacketCircle)
