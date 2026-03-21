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

Click **PDF** to generate a one-page report:

- Header with PacketCircle logo and report title
- Summary text: packet count, unique hosts, time range
- Circle visualization rendered with white background and high-contrast labels (print-optimized)
- IP pair table: source, destination, packets, bytes
- Footer with generation timestamp

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
| **PDF** | Export one-page PDF report |
| **Line Thickness** | Toggle proportional line weight on/off |
| **⚙ Settings** | Configure ntopng, Malcolm/Arkime, CA cert, reset defaults |
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
*→ See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) if something isn't working*
