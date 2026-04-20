# PacketCircle — Features Reference

Complete feature reference with use cases, controls, and workflow tips.

→ For installation see [INSTALLATION.md](INSTALLATION.md) · For first-use walkthrough see [QUICKSTART.md](QUICKSTART.md)

---

## Visualization

### Circle View

Hosts appear as labeled nodes arranged around a circle. Each connection arc between two nodes represents a communication pair:

- **Color** — protocol of the highest-priority traffic on that connection (see Protocol Color Coding below)
- **Thickness** — proportional to traffic volume (packets or bytes, user-selectable)
- **Dotted / multicolor line** — connection uses both TCP *and* UDP; alternating colors make mixed-protocol pairs instantly visible

**Use case:** Quickly spot which hosts generate the most traffic, which are talking to unexpected destinations, and which protocols dominate a capture.

### Graph View

An interactive node-link diagram where each host is a hexagonal node and each connection is an edge. Complements the Circle View by making topology and anomalies visible — node position carries meaning depending on the chosen layout.

**Switching to Graph View** reveals a second toolbar row with Edge color, Node color, Layout, Re-layout, and Zoom controls. All other controls (Top N, search, pair list, protocol filters) remain active and are shared with the Circle View.

#### Node encoding

- **Size** — scales with total traffic volume (log scale); busier hosts are visually larger
- **Double-hexagon symbol** — same as Circle View; outer ring highlights on hover or search match
- **Color** — determined by the **Node** color mode selector:

| Node Mode | Colors | Best for |
|---|---|---|
| **Service / Port** | Each known TCP/UDP service has a distinct color (same legend as the service port legend) | Seeing what role each host plays — server, client, DNS resolver, etc. |
| **Role (Int/Ext)** | Blue = Internal (RFC-1918) · Red = External · Purple = MAC/Unknown · Amber = Broadcast | Spotting traffic crossing network boundaries |
| **Protocol** | Dominant L7 protocol, same palette as Circle View | Finding which application protocol drives each host |
| **Function** | Crimson = Remote Access (RDP/VNC/Citrix/AnyDesk) · Orange = Interactive Shell (SSH/Telnet) · Teal = Messaging (SIP/XMPP/IRC/MQTT) · Green = File Transfer (SMB/NFS/FTP/rsync) · Grey = Other | Grouping hosts by the type of service they provide; pairs naturally with Cluster layout |

#### Edge encoding

- **Thickness** — proportional to traffic volume (when Line Thickness is on)
- **Style** — solid line = bidirectional traffic; dashed line = one-way only
- **Opacity** — fades for low-confidence connections (very few packets)
- **Color** — determined by the **Edge** color mode selector:

| Edge Mode | Color scale | Best for |
|---|---|---|
| **Protocol** | Application protocol palette (same as Circle View) | Protocol overview — consistent with Circle View |
| **TCP Health** | Green ≥75% · Yellow 50–74% · Orange 28–49% · Red <28% | Finding broken, refused, or half-open TCP connections |
| **Anomaly Score** | Green ≤12% · Yellow 13–30% · Orange 31–55% · Red >55% | Detecting port scans, floods, exfiltration, legacy insecure protocols |
| **Response Time** | Green <5 ms · Yellow-green 5–50 ms · Yellow 50–200 ms · Orange 200–500 ms · Red >500 ms | Identifying slow servers or high-latency paths |
| **Throughput** | Blue <10 KB/s · Green 10–100 KB/s · Yellow 100 KB–1 MB/s · Orange 1–10 MB/s · Red >10 MB/s | Spotting bulk transfers or bandwidth hogs |
| **TCP Window** | Green = healthy · Yellow = mild pressure · Orange = constrained · Red = zero-window stall | Diagnosing receiver-side bottlenecks and TCP buffer exhaustion |
| **High Risk** | Grey = safe · Yellow = elevated (SSH, MQTT, SNMP) · Orange = high (RDP, WinRM, AnyDesk) · Red = critical (Telnet, FTP, VNC, raw X11) · Violet = VPN/TOR | Instant risk audit — hover an edge for a tooltip listing detected risk signals by name |

See **[graph-scores.md](graph-scores.md)** for the full scoring algorithm reference.

#### Legend click-to-filter

Both the node legend (bottom-left) and the edge legend (bottom-right) are clickable:

- **Click a legend row** to fade everything that doesn't match — only edges carrying that service/protocol (or nodes of that role) remain fully visible
- **Click the same row again** to clear the filter
- In **Service / Port** node mode, the filter is port-based: all connections that carry traffic on that port are highlighted, regardless of whether that port is the node's single dominant port

#### Layouts

Choose a layout from the **Layout** dropdown. Click **↺ Re-layout** to re-run from scratch (useful for Force-directed after dragging nodes).

| Layout | Best for |
|---|---|
| **Force-directed** | General-purpose starting point. Nodes that communicate heavily pull together; isolated ones push apart. Reveals organic clusters without prior knowledge of topology. Nodes can be dragged freely. |
| **Star** | Identifying the dominant talker. The busiest node anchors the centre; every other node radiates from it. Good for spotting a central server, DNS resolver, or scanning host. |
| **Circular** | Quick overview — all nodes and edges at a glance, with no positional bias. Equivalent to the Circle View layout; useful for direct comparison. |
| **Grid** | Large node counts where other layouts become crowded. Deterministic, sorted by traffic volume. Position has no semantic meaning; useful mainly when you need to read every label. |
| **Cluster** | Grouping adapts to the active Node colour mode: **Role** → by subnet/network role; **Function** → by service category (Remote Access / Shell / Messaging / File Transfer); **Service or Protocol** → by dominant port or protocol; Wi-Fi mode → by 802.11 frame type. Nodes in the same group share a coloured background blob; edges crossing blobs reveal inter-group traffic. Hold **Ctrl and drag** a blob to reposition the whole cluster group. |
| **Concentric** | Finding the most-connected nodes quickly. Inner ring = highest degree (most peers); outer rings = increasingly peripheral hosts. Useful for spotting hubs, multicast sources, or overly chatty clients. |
| **Hierarchical** | Validating expected network topology. Places hosts in tiers top-to-bottom: External → Gateway → Server → Client. Traffic flowing the wrong way (e.g. a client talking directly to the internet bypassing the gateway) stands out immediately. |
| **Radial** | Tracing propagation or reach from one host. BFS rings expand outward from the most-connected node — each ring is one hop further away, making it easy to see how far a host's influence extends. |

#### Navigation

| Action | How |
|---|---|
| Zoom in / out | Scroll wheel, or **+** / **−** buttons |
| Reset zoom | **1:1** button |
| Pan canvas | Middle-mouse drag, or **Space + left-drag** on empty canvas |
| Drag a node | Left-click and drag any node (Force-directed only) |
| Move cluster group | **Ctrl + left-drag** inside any cluster blob (Cluster layout only) |

#### Interaction

- **Hover an edge** — highlights the corresponding pair row in the pair list
- **Click an edge** — opens the Connection Details popup (same as Circle View)
- **Click a node** — selects all pairs involving that host
- **Search** — same search bar as Circle View; matching nodes get a gold highlight ring in the graph

### Table View

Toggle to a flat list of all communication pairs with source, destination, protocol, packet count, and byte count columns. Sortable. Useful for exporting or reviewing large captures where the circle becomes crowded.

### Top N Conversations

Limit the circle to the **Top 10, 25, or 50** pairs by volume. Reduces visual clutter on busy captures. Searches that return results outside the current Top-N automatically prompt you to expand the view.

### Protocol Color Coding

| Color | Protocol |
|---|---|
| Blue | TCP |
| Green | UDP |
| Dark orange | HTTP |
| Teal | HTTPS / TLS |
| Purple | SMB / CIFS |
| Red | ICMP |
| Pink/magenta | DNS |
| Cyan | MSSQL |
| Gold | SSH |
| Orange | FTP |
| Gray | ARP, STP, LLDP, infrastructure |
| Light gray | Unknown |

Mixed TCP+UDP connections show as dotted alternating-color lines.

---

## Protocol Information Dialogs

Right-click any connection in the **Connection Details** popup to access deep protocol inspection. PacketCircle reads data directly from Wireshark's dissection engine — no third-party parsers, no re-parsing. All results are filtered to the selected pair only.

See **[PROTOCOL-INFO.md](PROTOCOL-INFO.md)** for the complete reference (trigger ports, exact fields extracted).

### IP Mode — Supported Protocols

| Protocol | Trigger Port(s) | What You Get |
|---|---|---|
| **TLS / SSL** | 443, any TLS | Certificate chain, cipher suite, TLS version, SNI, ALPN, JA3/JA4 fingerprints |
| **HTTP** | 80, 8080 | Methods, status codes, URIs, host headers, server info, cookies, user agents |
| **SMB / CIFS & DCE/RPC** | 445, 135 | SMB dialect, shares, file operations, named pipes, RPC interface UUIDs |
| **Kerberos** | 88 | TGT/TGS tickets, principals, realms, encryption types, pre-auth data, errors |
| **Email (SMTP/IMAP/POP3)** | 25/465/587, 143/993, 110/995 | Senders, recipients, subjects, server banners, AUTH methods, STARTTLS |
| **SQL (MSSQL/MySQL/PgSQL)** | 1433, 3306, 5432 | Queries, database/schema, login, server version, errors |
| **VoIP / SIP** | 5060, 5061 | Call-IDs, SIP methods/codes, From/To URIs, RTP payload types, SSRCs |
| **DNS** | 53, 5353 (mDNS) | Query/response counts, NXDOMAIN names, response codes, resolved records |
| **DHCP** | 67, 68 | Message types, MAC→IP leases, DHCP options |
| **LDAP / LDAPS** | 389, 636, 3268, 3269 | Bind DNs, SASL mechanisms, search base/scope/filter, result codes, controls |
| **SNMP** | 161, 162 | SNMP version, community strings, PDU type counts, OIDs queried, trap info |
| **Syslog** | 514, 601, 6514 | Severity & facility breakdown, last 20 messages with timestamp and text |
| **SSH / SFTP / SCP** | 22 | Key exchange algorithms, cipher/MAC pairs, compression, channel types |
| **FTP** | 21, 20, 990 | Credentials in cleartext ⚠, PASV/PORT mode, FEAT capabilities, file paths, command log |
| **Telnet** | 23, 992 | Option negotiations, capabilities, reassembled session payload (1 KB) ⚠ |
| **NBNS** | 137 UDP | Name registration/release counts, name→IP resolution table |
| **NetBIOS Datagram** | 138 UDP | Datagram type breakdown, source/destination NetBIOS names |
| **NetBIOS Session (NBSS)** | 139 TCP | Session request/confirm/reject counts, calling↔called name pairs |
| **TCP Transport Details** | Any TCP | Flags, window size (min/max/avg), MSS, SACK/timestamps/window scale, RTT, retransmissions |
| **UDP Transport Details** | Any UDP | Payload size (min/max/avg), direction breakdown, fragmentation risk notes |

> ⚠ FTP and Telnet transmit credentials in cleartext — visible if present in the capture.

### MAC Mode — Supported Protocols

| Protocol | Trigger | What You Get |
|---|---|---|
| **Layer-2 Frame Details** | Any pair | EtherTypes, VLAN IDs, LLC/SAP, SNAP, frame/byte counts |
| **ARP** | ARP pairs | Who-has/is-at mappings, gratuitous ARP, spoofing hints |
| **STP** | STP/RSTP/MSTP | Root bridge, path cost, port roles, BPDU types, topology changes |
| **LLDP** | LLDP pairs | Chassis ID, port ID, system name/description, capabilities, LLDP-MED |
| **LACP** | LACP pairs | Actor/partner MACs, keys, ports, state flags, PDU counts |
| **EAP / 802.1X** | EAPOL pairs | EAP method, auth result, identity, frame type counts |
| **VLAN (802.1Q)** | 0x8100 rows | VLAN ID table, QinQ detection, PCP priority distribution |
| **MACsec (802.1AE)** | 0x88E5 pairs | E-bit, SC-bit, Association Numbers, Packet Number range, SCI values |

---

## Wi-Fi Monitoring Mode

Switch PacketCircle to **Wi-Fi mode** when analyzing 802.11 monitor captures. The circle visualization adapts:

- **Connection lines colored by RSSI signal quality**: green (Excellent ≥ −65 dBm), yellow (Good), orange (Fair), red (Poor ≤ −85 dBm)
- **Click any node** to open a Wi-Fi Station Detail popup: SSID, BSSID, channel, 802.11 standard, signal statistics (avg RSSI, range, sample count), traffic volume, frame type breakdown, management event counts
- **Wi-Fi search**: filter by MAC address, SSID, or signal quality keyword (`excellent`, `good`, `fair`, `poor`)

**Use case:** Identify weak Wi-Fi clients, spot hidden SSIDs, map station-to-AP associations, and find management flood events in a WLAN capture.

---

## Search

The search bar accepts multiple query types:

| Query Type | Examples | What It Does |
|---|---|---|
| IP address | `192.168.1.1` | Highlights all pairs involving that host |
| CIDR range | `10.0.0.0/8` | Highlights all pairs with addresses in the subnet |
| Port | `TCP 443`, `UDP 53` | Highlights all pairs using that port |
| Protocol category | `TCP`, `UDP`, `ARP`, `ICMP`, `Infrastructure`, `Unknown` | Highlights all pairs of that category |
| Protocol keyword | `TLS`, `HTTP`, `SMB`, `Kerberos`, `SMTP`, `LDAP`, `SSH`, `FTP`, `SNMP`, `Syslog`, `Telnet`, `NBNS`, `VoIP`, `MACsec`, … | Highlights all pairs with that application protocol |
| Wireshark filter fallback | Any other text | If no PacketCircle match, offers to apply as a Wireshark display filter and reload |

**Blinking red highlights** appear on matching nodes and pairs in both the circle and the pair list. Use **Select Results** to isolate matching pairs with one click.

### Application Protocol Keywords (full list)

IP mode: `TLS` / `SSL` / `HTTPS` · `HTTP` · `SMB` / `CIFS` · `Kerberos` / `KRB` · `SMTP` / `email` / `mail` · `IMAP` · `POP3` / `POP` · `SQL` / `MSSQL` · `MySQL` · `PostgreSQL` / `PGSQL` · `VoIP` / `SIP` · `LDAP` · `SNMP` · `Syslog` · `SSH` · `FTP` · `Telnet` · `NBNS` · `NBDGM` · `NBSS`

MAC mode: `MACsec` / `802.1AE`

---

## Filtering & Wireshark Integration

### Display Filter Integration

Select one or more pairs in the list and click **Filter** to apply a Wireshark display filter matching exactly those pairs. The filter respects the directional arrow (→ A→B only, ↔ both, ← B→A only). Click **Clear Filter** to remove it.

**Use case:** Isolate a suspicious conversation directly from the circle — no need to type filter expressions manually.

### Bidirectional Pair List

Each row represents one bidirectional connection. Click the arrow between endpoints to cycle:
- **↔** Both directions (default)
- **→** A→B only
- **←** B→A only

The applied Wireshark filter respects the chosen direction.

### Protocol Filtering (Legend Checkboxes)

Toggle protocol categories in the legend to show/hide pairs of that type. Toggling a category also checks/unchecks the corresponding rows in the pair list — making **Select Results** work seamlessly with protocol filtering.

### TCP Stream Analysis

Right-click any TCP connection row → **Follow TCP Stream**, **TCP Throughput Graph**, or **TCP Round-Trip Time Graph** to launch Wireshark's built-in analysis tools from within PacketCircle.

---

## Integrations

### ntopng Integration

Send the current capture to a local or remote **ntopng** instance for deep traffic analytics.

1. Open **⚙ Settings** → enable ntopng → configure host URL and credentials
2. The **Send to NTOP** button appears in the toolbar when ntopng is enabled
3. Click it to dispatch the capture

Supports custom CA certificates for SSL verification (configure in Settings → CA Certificate).

### Malcolm / Arkime Integration

Upload the current PCAP directly to a **Malcolm** instance:

1. Open **⚙ Settings** → enable Malcolm/Arkime → configure the Malcolm URL
2. Click **Upload to Malcolm** — the PCAP is uploaded with `tags=PacketCircle`
3. PacketCircle automatically opens the Arkime sessions view filtered to `tags==PacketCircle` and the upload time range

> Malcolm processes PCAPs in the background. If sessions are not immediately visible, reload the Arkime browser tab.

### Settings Menu (⚙)

The gear icon in the toolbar opens the consolidated settings dialog:
- Enable / disable ntopng integration
- Configure ntopng host, credentials, SSL settings
- Enable / disable Malcolm / Arkime
- Configure local CA certificate for custom SSL verification
- **Reset All Settings to Defaults** — removes preferences file, resets window size and all toggles

---

## Export

### PDF Report

Click **PDF** to generate a 3-page report:

- **Page 1 — Cover page:** PacketCircle logo, report title, and configurable metadata fields (Company Name, Prepared by, Project, Comments, Date)
- **Page 2 — Report page:** The currently active view (Circle, Table, or Graph) at high resolution; the full communication pair list; a protocol legend (Circle/Table) or graph legend (Graph) below the visualization
- **Page 3 — Explanation page:** Plain-language interpretation guidance for the active view, plus common sections covering the pair list, active filters, Top-N setting, and metric

Paper size (A4 or Legal, landscape) and all cover page fields are configured in **Settings → Configure Reports…**. Settings are saved in `~/.PacketCircle/settings.ini`.

---

## Controls Reference

| Control | Description |
|---|---|
| **Top 10 / 25 / 50** | Limit visible conversations by volume |
| **Packets / Bytes** | Metric used for line thickness |
| **Circle / Table** | Toggle visualization vs. tabular view |
| **MAC / IP** | Switch between Layer-2 and Layer-3 pair mode |
| **Select All / None** | Bulk pair selection |
| **Select Results** | Select only the pairs matching the current search |
| **Filter** | Apply Wireshark display filter for selected pairs |
| **Clear Filter** | Remove display filter and show all traffic |
| **PDF** | Export 3-page PDF report (cover, visualization + pair list, explanation) |
| **Line Thickness** | Toggle proportional line weight on/off |
| **Edge** (Graph) | Select edge color encoding: Protocol / TCP Health / Anomaly Score / Response Time / Throughput / TCP Window / High Risk |
| **Node** (Graph) | Select node color encoding: Service/Port / Role (Int/Ext) / Protocol / Function |
| **Layout** (Graph) | Select graph layout: Force-directed / Star / Circular / Grid / Cluster / Concentric / Hierarchical / Radial |
| **↺ Re-layout** (Graph) | Re-run the selected layout from scratch |
| **Zoom − / 1:1 / +** (Graph) | Zoom out, reset to 100%, zoom in (scroll wheel also works) |
| **⚙ Settings** | Configure ntopng, Malcolm/Arkime, CA cert, reset defaults |
| **Configure Reports…** (Settings) | Set paper size (A4/Legal), Company Name, Prepared by, Project, Comments for PDF cover page |
| **Protocol checkboxes** | Show/hide pairs by protocol category |
| **Directional arrow** | Click pair row to cycle → ↔ ← filter direction |
| **Search bar** | IP / CIDR / port / keyword / Wireshark filter fallback |

---

## Theme & Display

PacketCircle automatically adapts to **light and dark themes** based on Wireshark / OS settings. No configuration needed.

Long hostnames in the pair list are **truncated with "…"** dynamically based on available column width. MAC addresses also resize with the splitter.

User preferences are saved to `~/.PacketCircle/settings.ini` (Linux/macOS) or the equivalent on Windows: window size, position, splitter layout, display mode (IP/MAC), metric (Packets/Bytes), Top N, view (Circle/Table), and line thickness are all restored on next launch.

---

*→ See [PROTOCOL-INFO.md](PROTOCOL-INFO.md) for the full protocol info dialog reference*
*→ See [graph-scores.md](graph-scores.md) for the TCP Health and Anomaly Score algorithm details*
*→ See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) if something isn't working*
