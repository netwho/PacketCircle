# PacketCircle

<p align="center">
  <img src="PacketCircle.png" alt="PacketCircle Logo" width="128">
</p>

[![Version](https://img.shields.io/badge/version-0.4.6-blue.svg)](CHANGELOG.md)
[![Status](https://img.shields.io/badge/status-public%20beta-orange.svg)](CHANGELOG.md)
[![License: GPL v2](https://img.shields.io/badge/License-GPL%20v2-blue.svg)](LICENSE)
[![Wireshark](https://img.shields.io/badge/Wireshark-4.0.x%20%7C%204.2.x%20%7C%204.4.x%20%7C%204.6.x-1679A7.svg)](https://www.wireshark.org/)
[![C++/Qt6](https://img.shields.io/badge/C%2B%2B%2FQt6-Native-41CD52.svg)](https://www.qt.io/)
[![macOS](https://img.shields.io/badge/macOS-Universal%20Binary-000000.svg?logo=apple)](installer/macos-universal/)
[![Linux](https://img.shields.io/badge/Linux-x86__64-FCC624.svg?logo=linux&logoColor=black)](installer/linux-x86_64/)
[![Windows](https://img.shields.io/badge/Windows-x86__64-0078D6.svg?logo=windows&logoColor=white)](installer/windows-x86_64/)

**A native Wireshark plugin that turns packet captures into interactive circle diagrams** — with protocol color coding, deep protocol inspection, traffic volume indicators, and PDF report export.

> **Beta Status**: v0.4.6, fully functional, actively developed. Report issues via [GitHub Issues](https://github.com/netwho/PacketCircle/issues).

---

## Demo

▶️ **[Watch the intro video on YouTube](https://youtu.be/jg4O9rdUp_0)** — PacketCircle in action in under 4 minutes.

▶️ **[Watch the v0.4.x feature video on YouTube](https://www.youtube.com/watch?v=Q83vcK8hXJo)** — protocol info dialogs, Wi-Fi mode, bidirectional filtering, and more.

---

## What It Does

![PacketCircle Main View](screenshots/packetcircle-main.png)

*Hosts as nodes on a circle, connections as arcs — colored by protocol, weighted by traffic volume.*

**See who is talking to whom, using which protocol, and how much** — instantly, from any PCAP or live capture.

| Capability | Description |
|---|---|
| **Circle visualization** | Hosts as nodes, connections as arcs — colored by protocol, sized by volume |
| **20+ protocol info dialogs** | Right-click any connection: TLS certs, HTTP headers, FTP credentials, DNS answers, SSH key exchange, Kerberos tickets, and more |
| **Wi-Fi monitoring mode** | Visualize 802.11 captures with RSSI signal-quality color coding |
| **Smart search** | Search by IP, CIDR, port (`TCP 443`), protocol keyword (`TLS`, `SSH`, `SNMP`, …), or any Wireshark display filter |
| **Wireshark integration** | Apply display filters, follow TCP streams, open throughput/RTT graphs — all from within PacketCircle |
| **ntopng & Malcolm/Arkime** | One-click send to ntopng or upload PCAP to Malcolm/Arkime with automatic Arkime session filter |
| **PDF export** | One-page report with circle visualization, pair table, and capture summary |
| **Cross-platform** | macOS Universal Binary (Intel + Apple Silicon), Linux x86_64, Windows x86_64 |

---

## Screenshots

### Circle View & Filtering

![Filter](screenshots/packetcircle-filter.png)

*Select a pair and apply a precise Wireshark display filter directly from the circle.*

### Protocol Information Dialogs

![Protocol Details](screenshots/PacketCircelProtDetails.png)

*Right-click any connection line: HTTP, TLS/SSL, SMB, Kerberos, Email, SQL, VoIP — and 13 more protocols.*

### Wi-Fi Monitoring Mode

![Wi-Fi Mode](screenshots/WiFi-Circle.png)

*802.11 captures: RSSI-based color coding (green = excellent, red = poor). Click any node for signal stats, frame breakdown, and management events.*

### Connection Popup & Context Menu

![Connection Popup](screenshots/packetcircle-connection-popup.png)

*Click a line to see per-port details. Right-click to filter, follow a TCP stream, or open protocol info.*

---

## Quick Install

> All installers detect your Wireshark version, show any existing installation, and offer uninstall. Just run and follow the prompts.

**macOS** (Intel & Apple Silicon — Wireshark 4.6.x):
```bash
cd installer/macos-universal && chmod +x install.sh && ./install.sh
```

**Linux** (x86_64 — Wireshark 4.0 / 4.2 / 4.4 / 4.6, auto-detected):
```bash
cd installer/linux-x86_64 && chmod +x install.sh && ./install.sh
```

**Windows** (x86_64 — Wireshark 4.6.x):
```cmd
cd installer\windows-x86_64 && install.bat
```

→ **Full installation guide, manual install, and uninstall:** [INSTALLATION.md](INSTALLATION.md)

---

## Supported Platforms

| Wireshark Version | macOS Universal | Windows x86_64 | Linux x86_64 |
|---|---|---|---|
| **4.6.x** | ✓ | ✓ | ✓ |
| **4.4.x** | — | — | ✓ |
| **4.2.x** | — | — | ✓ |
| **4.0.x** | — | — | ✓ ¹ |

> ¹ Wireshark 4.0.x on Linux requires Qt6 (`libqt6widgets6`). The installer detects this and offers to install it.

---

## Documentation

| Document | Contents |
|---|---|
| **[INSTALLATION.md](INSTALLATION.md)** | Platform installers, manual install, prerequisites, uninstall |
| **[FEATURES.md](FEATURES.md)** | Every feature explained with use cases and controls reference |
| **[QUICKSTART.md](QUICKSTART.md)** | First-use walkthrough — up and running in 5 minutes |
| **[TROUBLESHOOTING.md](TROUBLESHOOTING.md)** | Common errors, platform-specific fixes, diagnostic tools |
| **[PROTOCOL-INFO.md](PROTOCOL-INFO.md)** | All 20+ protocol info dialogs — fields extracted, trigger ports |
| **[CHANGELOG.md](CHANGELOG.md)** | Full version history |

---

## License

GNU General Public License v2 — see [LICENSE](LICENSE).

## Acknowledgments

- **Wireshark development team** — for the outstanding dissector framework and plugin API that makes deep protocol inspection possible
- **Wireshark community** — for testing, feedback, and bug reports that shaped every release
- **AI-Assisted** — yes (Claude by Anthropic) — used for build system automation, installer scripting, cross-platform compatibility, protocol info dialogs, and documentation

---

**Built with ❤️ for the network analysis community** — [github.com/netwho/PacketCircle](https://github.com/netwho/PacketCircle)
