# PacketCircle — Quick Start

Get up and running in under 5 minutes.

→ **Need to install first?** See [INSTALLATION.md](INSTALLATION.md) for full platform instructions.

---

## Step 1 — Get the installer & install

**No git?** **[⬇ Download installer.zip](https://github.com/netwho/PacketCircle/raw/main/installer.zip)** — unzip it and you have the `installer/` folder ready to go. No account needed.

**git users:** `git clone https://github.com/netwho/PacketCircle.git`

Then run the installer for your platform and follow the prompts. Always choose **v.0.5.2** (latest). v.0.4.7 is the last v0.4.x release.

| Platform | From the `installer/` folder |
|---|---|
| **macOS** | `cd macos-universal && chmod +x install.sh && ./install.sh` |
| **Linux** | `cd linux-x86_64 && chmod +x install.sh && ./install.sh` |
| **Windows** | `cd windows-x86_64` → double-click `install.bat` |

Restart Wireshark after installing.

---

## Step 2 — Open a Capture

Open Wireshark and load a PCAP/PCAPNG file, or start a live capture.

---

## Step 3 — Launch PacketCircle

Go to **Tools → PacketCircle**. The PacketCircle window opens alongside Wireshark.

---

## Step 4 — Explore the Circle

- **Nodes** around the circle = network endpoints (IP or MAC addresses)
- **Arcs** between nodes = communication pairs
- **Arc color** = highest-priority protocol observed on that connection
- **Arc thickness** = traffic volume (packets or bytes, your choice)
- **Dotted alternating-color arc** = connection uses both TCP and UDP

---

## Step 5 — Interact

| Action | Result |
|---|---|
| **Hover** over a node | See IP, packet counts, destination ports, and service names |
| **Click an arc** in the circle | Open the Connection Details popup with per-port breakdown |
| **Right-click** a row in Connection Details | Apply display filter · Follow TCP stream · Open protocol info dialog |
| **Check/uncheck** pairs in the list | Select which pairs are shown on the circle |
| **Click "Filter"** | Apply a Wireshark display filter for the selected pairs |
| **Click "Clear Filter"** | Remove the display filter |
| **Click "PDF"** | Export a one-page report |

---

## Step 6 — Adjust the View

| Control | What It Does |
|---|---|
| **Top 10 / 25 / 50** | Limit the circle to the busiest N conversations |
| **Packets / Bytes** | Switch the metric for arc thickness |
| **Circle / Table / Graph** | Switch between circle visualization, flat table, and interactive topology graph |
| **MAC / IP** | Toggle Layer-2 (MAC) vs Layer-3 (IP) pair mode |
| **Protocol checkboxes** | Show/hide pairs by protocol type |
| **⚙ Settings** | Configure ntopng, Malcolm/Arkime, CA cert, reset defaults |

---

## Step 7 — Graph View

Switch to **Graph** view for a topology-based perspective:

- **Layout** — choose from 8 arrangements: Force-directed (organic clusters), Star (busiest host at centre), Circular, Grid, Cluster (by subnet), Concentric (most-connected inner), Hierarchical (External→Gateway→Server→Client), Radial
- **Edge color** — switch to TCP Health, Anomaly Score, Response Time, or Throughput to spot problems at a glance
- **Node color** — Service/Port (what each host does), Role (internal/external), or Protocol
- **Legend click** — click any legend row to highlight only connections carrying that service or protocol
- **Right-click the pair list** — Select All / Select None / Invert Selection / Select Search Results

---

## Tips

- **Search by protocol**: Type `TLS`, `SSH`, `SMB`, `FTP`, `SNMP`, `Telnet`, `NBNS`, `VoIP`, or any other protocol keyword to highlight all matching pairs instantly.
- **Deep protocol inspection**: Right-click any connection → protocol info dialog. FTP shows credentials. TLS shows certificates. DNS shows resolved names. 20+ protocols supported.
- **Isolate a conversation**: Right-click the pair list → Select None, check the pair you want, click Filter — Wireshark zooms in on that conversation.
- **Bidirectional filtering**: Click the ↔ arrow on a pair row to cycle to → (A→B only) or ← (B→A only) before applying the filter.
- **Wi-Fi captures**: If your capture is from a wireless monitor interface, the circle color-codes connections by RSSI signal quality.
- **PDF report**: Click **PDF** at any time — circle, pair table, and capture summary in one page.
- **Graph view**: Switch to Graph → Hierarchical to instantly see if any client is bypassing gateways. Use Anomaly Score edge coloring to find port scans and exfiltration at a glance.
- **Select pairs**: Right-click the pair list to Select All, Select None, or Invert Selection — then click Filter to apply a Wireshark display filter for exactly those conversations.

---

## Uninstalling

Re-run the installer and choose **u) Uninstall**, or remove the plugin file manually:

```bash
# macOS
rm ~/.local/lib/wireshark/plugins/4-6/epan/packetcircle.so

# Linux
rm ~/.local/lib/wireshark/plugins/*/epan/packetcircle.so
```

```powershell
# Windows
Remove-Item "$env:APPDATA\Wireshark\plugins\4.6\epan\packetcircle.dll"
```

Restart Wireshark after uninstalling.

---

→ **Something not working?** See [TROUBLESHOOTING.md](TROUBLESHOOTING.md)
→ **Full feature reference:** [FEATURES.md](FEATURES.md)
→ **Protocol info dialogs:** [PROTOCOL-INFO.md](PROTOCOL-INFO.md)
