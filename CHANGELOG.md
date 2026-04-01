# Changelog

All notable changes to PacketCircle will be documented in this file.

## [0.4.7] - 2026-04-01

### Added
- **Table view: left-click opens Connection Details** — Clicking any row in the Table view now opens the same Connection Details popup that appears when clicking a circle arc in the Circle view. Previously the table was display-only; it is now fully interactive.
- **Table view: right-click context menu** — Right-clicking any table row shows a grouped context menu with two sections:
  - *Wireshark* — Apply Filter in Wireshark, Follow TCP Stream, TCP Throughput Graph, TCP Round-Trip Time Graph (TCP-only items are greyed out for UDP pairs)
  - *PacketCircle* — Protocol Information dialog for the top destination port (same 18 protocols as the circle-view popup), TCP / UDP Transport Details, Connection Details
- **Malcolm/Arkime: precise capture time window** — The Arkime sessions URL generated after a successful Malcolm upload now includes the actual first/last packet timestamps from the capture file (`startTime` / `stopTime` parameters with a 60-second buffer on each side). Previously the URL used no time filter. Requires at least one packet in the capture file.
- **`circle_vis_get_capture_time_range()`** — New C bridge function in `ui_bridge.cpp` that reads the first and last `frame_data.abs_ts` values directly from Wireshark's frame sequence, returning Unix epoch seconds.

### Changed
- **Connection Details popup context menu: grouped sections** — The right-click menu inside the Connection Details popup now uses `QMenu::addSection()` to separate *Wireshark* actions (filter, follow stream, throughput/RTT graphs) from *PacketCircle* actions (protocol info, transport details, supported protocols). Redundant separators removed.

- AI-Assisted: yes (Claude) — table view interactivity, right-click context menu, Malcolm time-range fix, bridge API, documentation

## [0.4.6] - 2026-03-18

### Added
- **New protocol information dialogs** — Ten additional right-click protocol info dialogs, each triggered only when the destination port matches. All results are filtered to the selected pair:
  - **LDAP / LDAPS** (ports 389, 636, 3268, 3269) — session summary, bind DNs, SASL mechanisms, search operations (base DN, scope, filter strings), modify/add/delete counts, result codes, request/response control OIDs
  - **SNMP** (ports 161, 162) — SNMP version (v1/v2c/v3), community strings, PDU type counts (GetRequest, GetNextRequest, GetBulk, SetRequest, Response, Trap, InformRequest), OIDs queried or reported, trap enterprise OID and generic/specific trap codes, error status codes
  - **Syslog** (ports 514 UDP/TCP, 601 TCP, 6514 TLS) — matched packet count, transports detected (UDP/TCP/TLS), severity breakdown (Emergency → Debug), facility breakdown (kern/user/mail/daemon/auth/cron/local0–7), last 20 messages with timestamp, severity, facility, and message text
  - **SSH / SFTP / SCP** (port 22) — key exchange algorithm negotiation (kex algorithms, host key algorithms), cipher and MAC algorithm pairs (client→server and server→client), compression algorithms, channel open/close counts and channel types (session, direct-tcpip, forwarded-tcpip); note: SSH payloads are encrypted, only handshake metadata is visible
  - **FTP** (ports 21, 20, 990) — auth result and credentials (username/password in cleartext), data transfer mode (PASV/PORT), FEAT server capabilities, all FTP commands with counts sorted by frequency (PASS highlighted in red), files and paths seen in RETR/STOR/NLST/LIST, chronological command log (up to 200 entries)
  - **Telnet** (ports 23, 992) — matched packet count, option negotiations (WILL/DO in green, WONT/DONT in amber), capabilities detected (Echo, Linemode, NAWS, Terminal Type, Authentication, Encryption), reassembled Telnet payload (up to 1 KB) in a monospace scrollable block
  - **NBNS — NetBIOS Name Service** (port 137 UDP) — query/response/registration/release/WACK/refresh counts, name→IP resolution table (deduplicated) from all responses
  - **NetBIOS Datagram Service** (port 138 UDP) — datagram type breakdown (Direct Unique, Direct Group, Broadcast, Error), source NetBIOS names with packet counts, destination NetBIOS names with packet counts
  - **NetBIOS Session Service (NBSS)** (port 139 TCP) — session request/confirm/reject/retarget/keepalive/message counts, calling↔called name pairs from session request packets
  - **SMB / DCE-RPC** trigger updated — port 139 TCP is now handled exclusively by the NBSS dialog; SMB info is triggered on ports 445 and 135 only
  - **TCP Transport Details** (any TCP pair) — transport-layer statistics for the selected pair/port: flags observed (SYN/ACK/FIN/RST/PSH/URG/ECE/CWR as colour-coded pills), window size min/max/avg, MSS from SYN options, negotiated TCP options (SACK Permitted, Timestamps, Window Scale with multiplier), RTT min/max/avg in ms from `tcp.analysis.ack_rtt`, retransmission and out-of-order packet counts. Available on every TCP connection via "TCP Transport Details…" in the right-click menu, alongside any port-specific application-layer dialog
  - **UDP Transport Details** (any UDP pair) — payload size statistics (min/max/avg bytes per datagram, derived from `udp.length − 8`), traffic direction breakdown (A→B / B→A packet counts with percentages and an ASCII asymmetry bar), datagram characteristic notes (fixed-size detection, fragmentation risk warning for datagrams > 1472 bytes). Available on every UDP connection via "UDP Transport Details…" in the right-click menu
- **ntopng Integration** — Send the current capture file to a ntopng instance for deep traffic analysis. Configure host URL and credentials via the Settings menu (⚙). The "Send to NTOP" button is shown only when ntopng is enabled in settings
- **Malcolm / Arkime Integration** — Upload the current PCAP directly to a Malcolm/Arkime instance via multipart POST with `tags=PacketCircle`. After a successful upload, automatically opens the Arkime sessions view pre-filtered with a time range and `expression=tags==PacketCircle`. Post-upload dialog notes that Malcolm processes PCAPs in the background and advises to reload the browser if results are not immediately visible
- **Settings Menu** (⚙ gear icon) — Consolidated settings dialog next to the help button covering:
  - Enable/disable ntopng integration (controls "Send to NTOP" button visibility)
  - "Configure ntopng…" button (host, credentials, SSL settings)
  - Enable/disable Malcolm / Arkime integration (greyed out — not yet implemented)
  - "Configure Local CA Certificate…" for custom SSL certificate verification
  - **Reset All Settings to Defaults** — confirmation dialog, removes the INI preferences file, resets window size and all toggles to factory defaults

### Changed
- **Protocol info menu** — Context menu options are greyed out with the required port shown in parentheses when not applicable to the selected connection. Port 139 TCP now dispatches to the new NBSS dialog instead of SMB
- **Settings persistence** — ntopng and Malcolm enabled/disabled state is now saved in the INI preferences file under `[Integrations]`

### Fixed
- **Malcolm upload tags** — Uploads now include a `tags=PacketCircle` multipart field so uploaded sessions can be isolated in the Arkime session browser using the `tags==PacketCircle` filter expression
- **Malcolm Arkime URL** — Sessions URL now includes `&expression=tags%3D%3DPacketCircle` for accurate post-upload session filtering

- AI-Assisted: yes (Claude) — all ten new protocol info dialogs, ntopng integration, Malcolm/Arkime integration, settings menu, NBNS/NBDGM/NBSS packet_analyzer extractors, TCP/UDP transport details dialogs, fvalue_t opaque-pointer compat fixes, documentation

## [0.4.4] - 2026-03-15

### Added
- **Protocol-info keyword search** — The search bar now accepts friendly keywords for every protocol that has a protocol information popup. Typing the keyword highlights all pairs using that protocol and supports "Not in Top-N" full-buffer lookup. New IP-mode keywords: `TLS` / `SSL` / `HTTPS` (ports 443, 465, 993, 995, 8443), `HTTP` (ports 80, 8080, 8000, 8888), `SMB` / `CIFS` (ports 445, 139), `Kerberos` / `KRB` (port 88), `SMTP` / `email` / `mail` (ports 25, 465, 587), `IMAP` (ports 143, 993), `POP3` / `POP` (ports 110, 995), `SQL` / `MSSQL` (port 1433), `MySQL` (port 3306), `PostgreSQL` / `PGSQL` (port 5432), `VoIP` / `SIP` (ports 5060, 5061). New MAC-mode keyword: `MACsec` / `802.1AE` (EtherType 0x88E5).
- **Wireshark display filter fallback** — When a search term returns no PacketCircle results (either unrecognised keyword or zero pair matches), PacketCircle now asks whether to apply the query as a Wireshark display filter. The user is warned about potential additional processing time on large captures. If confirmed: the filter is applied to Wireshark, PacketCircle re-analyses the filtered packet set (400 ms delay), and the view is reloaded. If the filter produces no matching packets the message ":-( no packets found in the buffer" is shown. If the user declines, the search help dialog is shown instead.

### Changed
- **Search help dialog updated** — IP mode help now lists the new protocol-info keywords under a dedicated "Protocol info keywords" section. MAC mode help adds MACsec / 802.1AE. All modes show an explanatory note about the display filter fallback.
- **Installer paths** — Installer directories renamed from `installer-v.0.4.x/` to `installer/` for a cleaner repository layout. Old version binaries moved to `binary-backup/` per platform.

### Fixed
- **Linux: GLIBC_2.38 dependency on older distributions** — Binaries built on Ubuntu 24.04 (glibc 2.39) referenced `__isoc23_sscanf` and `__isoc23_strtoul` (C23 glibc 2.38 variants), causing a load error on Debian 12, Ubuntu 22.04, and similar distributions with glibc < 2.38. Root cause: `_GNU_SOURCE` (set by the Wireshark build system) implicitly enables `_ISOC2X_SOURCE`, which causes glibc 2.38+ headers to redirect `sscanf`/`strtoul` to their C23 variants. Fixed with a small `glibc_compat.c` shim compiled without `_GNU_SOURCE`, providing weak `__isoc23_sscanf` and `__isoc23_strtoul` wrappers that call the standard `vsscanf`/`strtoul`. The linker resolves these references locally, eliminating the GLIBC_2.38 requirement from the `.so`. All four Linux binaries (ws40 / ws42 / ws44 / ws46) are fixed.
- **Plugin version reported incorrectly** — `set_module_info` in `CMakeLists.txt` was not updated from v0.4.2, causing Wireshark's Help → About → Plugins list to show the wrong version. Now correctly reports v0.4.4.
- **Wireshark 4.0.x: Qt6 runtime required** — The pre-built ws40 binary links against Qt6 (Wireshark 4.0.x supports both Qt5 and Qt6 at build time; the shipped binary uses Qt6). Systems running Wireshark 4.0.x from a distribution package may not have Qt6 installed. The installer now detects this and provides the `libqt6widgets6` install command if needed.
- AI-Assisted: yes (Claude) — protocol-info keyword search, display filter delegation, glibc compat shim, search help updates, installer layout, CHANGELOG

## [0.4.3] - 2026-03-11

### Added
- **VLAN (802.1Q) Information Dialog** — Right-click any `0x8100` row in the MAC-mode protocol breakdown table to open a VLAN session summary. Shows: matched frame count, QinQ (double-tagged) frame count, DEI/CFI bit count, a VLAN ID table sorted by frame count (ID → frames), and a PCP (Priority Code Point) distribution with IEEE 802.1p class names (Best Effort, Background, Excellent Effort, Critical Applications, Video, Voice, Internetwork Control, Network Control).

### Fixed
- **Bug: MACsec dialog showed "no data" / "SecTAG fields not decoded"** — The MACsec extractor previously relied exclusively on `macsec.*` dissector fields from Wireshark's tree. When the MACsec dissector is inactive or the frame is only partially decoded, those fields are absent even though the EtherType `0x88E5` is present. Fixed with a TVB raw-byte fallback: when `eth.type == 0x88E5` is found but no `macsec.*` fields are decoded, the SecTAG is parsed directly from the packet bytes (TCI/AN byte, Packet Number, SCI). The per-frame walk context is now reset for each matched frame so the fallback flags do not carry over between frames. The `found` condition is relaxed to `matched > 0` so the dialog always opens when MACsec traffic is present.
- **Bug: MACsec dialog showed outdated / placeholder fields** — The dialog now displays meaningful data from the TVB fallback: E-bit (encryption enabled), SC-bit (SCI present), AN (Association Number) distribution table, Packet Number range (min / max), and SCI values with format explanation.

### Improved
- **MAC-mode popup: instant display with loading indicator** — The MAC-mode Connection Details popup now appears immediately with a "Scanning packets…" placeholder row instead of blocking the UI. A thin animated progress bar (5 px, blue gradient) indicates background scanning. Once the frame scan completes the placeholder is replaced by the real protocol breakdown table and the progress bar is hidden.
- **MAC-mode popup: dynamic window sizing** — After the protocol breakdown table is populated the popup resizes itself to fit the table content (capped at 300 px table height), removing unused whitespace for captures with few distinct EtherTypes.
- **MAC-mode popup: removed redundant "Apply Filter" button** — The per-row right-click context menu already provides "Apply Filter in Wireshark"; the separate button below the table was removed to reduce clutter.
- **Linux Wireshark 4.0.x support** — Added pre-built `.so` binary for Wireshark 4.0.x (built against 4.0.17 on Ubuntu 22.04 with Qt6). Required a source-level API compatibility shim (`PC_FI_VALUE` macro) to handle the `field_info.value` type change between WS 4.0 (`fvalue_t` struct by value) and WS 4.2+ (`fvalue_t*` pointer). Debian stable ships Wireshark 4.0.x in its package repository.
- **Linux binaries rebuilt** — Pre-built `.so` binaries for Linux x86_64 (Wireshark 4.0.x, 4.2.x, 4.4.x, 4.6.x) have been rebuilt from the v0.4.3 source and updated in the installer package. The unified installer now auto-detects all four series and offers only the versions compatible with the detected Wireshark release.
- AI-Assisted: yes (Claude) — VLAN dialog, MACsec TVB fallback + richer dialog, MAC popup UX improvements, Linux rebuild

## [0.4.2] - 2026-03-09

### Added
- **DNS Information Dialog** — Right-click any DNS connection (port 53 / mDNS port 5353) in the Connection Details popup to see a full DNS session summary: total packets, query/response counts, recursion desired flag, DNS-over-TCP detection, NOERROR/NXDOMAIN/SERVFAIL/REFUSED response code breakdown, query type histogram (A, AAAA, CNAME, MX, TXT, SRV, PTR, …), top queried domains with per-name counts, resolved answer records (name → type → value), and NXDOMAIN names. Results are filtered to the selected pair only (IP addresses + port).
- **mDNS (port 5353) protocol detection** — mDNS traffic is now recognised as a distinct protocol in pair classification and the category search (IP mode), consistent with DNS at port 53.
- **DHCP protocol detection** — DHCP (ports 67/68) and GRE/ESP/AH/IKE tunnel protocols are now promoted to their protocol name instead of remaining "UDP" in pair classification, enabling accurate category filtering and search.

### Fixed
- **Bug: Category legend not updating after search** — When a search entered override mode (results outside Top-N), the protocol category checkboxes in the legend still reflected the pre-filter Top-N set instead of the matched pairs. Fix: `updateLegend()` is now called after `updateViews()` in `enterSearchOverrideMode()`, `exitSearchOverrideMode()` (clear-search path), and the Top-10/25/50 button handlers.
- **Bug: DNS / protocol-info dialogs showing data for entire trace** — The DNS extractor used `(void)addr_a; (void)addr_b;` and scanned the full capture regardless of which pair was clicked. Fixed by adding bidirectional address + port filtering (same pattern as TLS/HTTP/SMB), so the dialog now shows only traffic for the selected connection pair.
- **Bug: SIGSEGV crash in Connection Popup context menu** — During heavy frame scans (TLS, HTTP, SMB, Kerberos, Email, SQL, VoIP etc.), `circle_vis_pump_events()` processed Qt events mid-scan. A mouse-leave event restarted the auto-close timer, which fired and called `deleteLater()` while the popup was still scanning. The subsequent `hide()` call crashed with a Pointer Authentication (PAC) violation on ARM64. Fix: `m_contextMenuActive` is no longer reset after `menu.exec()` returns — it stays `true` throughout any action that involves a frame scan. Only the dismiss-only path resets it.
- **Bug: ARP/STP/LLDP search returned no results in MAC view** — The tap listener registered with `TL_REQUIRES_NOTHING` left `pinfo->current_proto` as "Ethernet" for L2-only protocols. The pair's `top_protocol` ended up as "Ethernet", so searching for "ARP", "STP", or "LLDP" matched nothing. Fix: added Priority 1.4 detection using `proto_is_frame_protocol(pinfo->layers, ...)` for ARP, RARP, STP, LLDP, LACP, CDP, VTP, EAPOL, EAP, and LLC — the same reliable technique used for ICMP since v0.4.1.
- **Bug: ICMP type label memory leak in `walk_icmp_proto_tree()`** — `g_hash_table_replace()` allocated a new key string with `g_strdup()` but `type_labels` still held a pointer to the old (now freed) key, creating both a memory leak and a potential use-after-free. Fix: replaced with `g_hash_table_lookup_extended()` + `g_hash_table_steal()` to update the count in-place using the original key pointer — no new allocation, no stale pointer.
- **Bug: Wrong type passed to `proto_is_frame_protocol()`** — The ICMP extraction function was passing `fdata->pfd` (a `GSList *`) where `wmem_list_t *` is expected, causing a compiler warning and potential misbehaviour. Corrected to `edt->pi.layers` which carries the same protocol stack information with the correct type.
- **Bug: EtherType hex search accepted but never matched** — The search bar accepted `0x0806`, `0x0800` etc. but could not match pairs because pairs store protocol names, not EtherType numbers. Removed the EtherType hex search entirely; protocol names (`arp`, `ipv4`, etc.) already work case-insensitively.

### Improved
- **"Not in Top-N" search dialog** — The confirmation dialog shown when search results fall outside the current Top-N view now uses an HTML `<ul>` list for the "If you continue:" bullet points, ensuring consistent indentation when text wraps, and is sized wide enough to fit all three bullets on single lines.
- **Protocol info dialogs: NULL guard after `epan_dissect_new()`** — All 16 extraction functions (TLS, HTTP, SMB, Kerberos, Email, SQL, VoIP, L2, STP, LLDP, LACP, EAP, MACsec, ARP, DHCP, ICMP) and the main analysis loop now check the return value of `epan_dissect_new()` and return an empty-but-valid result on OOM rather than crashing.
- **Eliminated ~93 per-packet debug log lines** — The tap callback and all extraction functions contained `LOG_LEVEL_WARNING` traces that fired on every packet (up to hundreds of thousands of calls on large captures). These have been removed or demoted to `LOG_LEVEL_INFO`/`LOG_LEVEL_ERROR` as appropriate, significantly reducing log noise and I/O overhead on large captures.
- **Version strings corrected** — `PLUGIN_VERSION_MINOR` in `circle_plugin.h` was stuck at 3 (should be 4). All five version locations now consistently report v0.4.2.
- AI-Assisted: yes (Claude) — crash fixes, L2 protocol detection, ICMP memory fix, NULL guards, debug log cleanup, version bump, documentation

## [0.4.1] - 2026-03-05

### Fixed
- **Bug: IPv6 display filters** — Wireshark rejected filters like `ip.src == 2001:db8::1` because `ip.src`/`ip.dst` only accept IPv4 addresses. `createFilterString()` now detects IPv6 addresses (by colon presence) and emits `ipv6.src`/`ipv6.dst` instead.
- **Bug: MAC address truncation ignored resize** — MAC addresses were always abbreviated to the fixed `aa:..ff` form regardless of available column width. They now pass through `truncateIPv6Address()` unchanged and are width-truncated by the same `truncateDisplayName()` path used for hostnames and IPv4 addresses, so the display adapts dynamically when the splitter is moved.
- **Bug: MAC/IP mode lost on restart** — Opening PacketCircle after saving MAC mode showed the correct button state but re-analysed the capture in IP mode. `circle_vis_open_window()` now passes `getUseMAC()` (restored from preferences before the window is shown) to `packet_analyzer_analyze()`, so the initial pair list always matches the saved mode.

### Changed
- **Bidirectional pairs collapsed to one row** — The connection pair list now shows a single row per bidirectional connection instead of two. The arrow between the two endpoints is a toggle: clicking the row (outside the checkbox) cycles the direction through **→** (apply filter for A→B only), **↔** (both directions, the default), and **←** (B→A only). The Wireshark display filter generated by "Apply Filter" respects the current arrow direction.

## [0.4.0] - 2026-02-25

### Added
- **Protocol Category Search** - Type a category name in the search field (`TCP`, `UDP`, `ARP`, `ICMP`, `Infrastructure`, `Unknown`) to highlight all pairs belonging to that category, then use "Select Results" to isolate them
- **Protocol Category → Pair List Sync** - Toggling protocol category checkboxes (e.g. TCP, UDP, Infrastructure) now also checks/unchecks the corresponding pairs in the pair list, enabling "Select Results" to work with protocol filtering
- **IGMP Multicast Detection** - IPv4 packets with multicast destinations (224.0.0.0/4) are now correctly classified as IGMP / Infrastructure instead of "Unknown"
- **Protocol Information Dialogs** - Right-click a connection in the Connection Details popup to access deep protocol inspection for seven protocol families:
  - **TLS/SSL Information** - Certificate details (subject, issuer, validity, SANs), negotiated cipher suites, TLS version, ALPN, SNI, JA3/JA4 fingerprints
  - **HTTP Information** - Request/response details including methods, status codes, URIs, content types, server headers, cookies, and user agents
  - **SMB/CIFS & DCE/RPC Information** - Share names, file operations, tree operations, named pipe access, DCE/RPC interface UUIDs, and operation names
  - **Kerberos Information** - Ticket details (TGT/TGS), client and server principals, realms, encryption types, pre-authentication data, and service principal names
  - **Email Information (SMTP/IMAP/POP3)** - Senders, recipients, subjects, server responses, authentication methods, IMAP mailbox operations, and POP3 commands
  - **SQL Database Information (MSSQL/MySQL/PostgreSQL)** - Queries, database/schema names, authentication details, server version, application name, command/response statistics, and error messages
  - **VoIP/SIP Information** - SIP Call-IDs, method/status code counts, From/To addresses, user agents, RTP payload types and SSRCs, RTP setup methods, and H.223 mux entries
- **Protocol-Aware Context Menu** - Connection popup context menu dynamically shows relevant protocol info options based on the destination port (e.g., TLS Info for port 443, SQL Info for ports 1433/3306/5432, VoIP Info for ports 5060/5061)
- **Reusable Dialog Helpers** - Extracted common UI helpers (`createInfoDialog`, `addHtmlTextEdit`, `renderHashCountTable`, `addCloseButton`, `addSorryPlaceholder`) for consistent protocol information dialog presentation
- AI-Assisted: yes (Claude) — protocol info dialogs, installer redesign (version selection, downgrade, uninstall), Linux build automation, documentation

## [0.3.2] - 2026-02-16

### Added
- **TCP Stream Statistics** - Connection popup context menu now includes TCP Throughput Graph and TCP Round-Trip Time Graph, launching Wireshark's built-in TCP stream analysis tools
- **Select Search Results** - New "Select Results" button that selects only the communication pairs matching the current search, deselecting all others
- **Theme-Aware UI** - Plugin automatically adapts to light and dark themes based on Wireshark/OS settings
- **Port Search** - Search bar supports TCP/UDP port queries (e.g., `TCP 443`, `UDP 53`) to highlight matching communication pairs
- **Name Truncation** - Long resolved hostnames in the pair list are truncated with "..." when space is limited

### Changed
- Help button enlarged (30x30) and right-aligned in the toolbar for better visibility
- Help dialog version corrected and updated with all new features
- Version bumped to 0.3.2

### Fixed
- IP fragment protocol classification no longer misidentifies fragments as ICMP or TCP
- Bidirectional filter generation uses `ip.addr` / `eth.addr` for correct two-way matching
- AI-Assisted: yes (Claude) — TCP stream statistics integration, theme-aware UI, installer improvements, documentation

## [0.3.1] - 2026-02-15

### Added
- **User Preferences Persistence** - Window size, position, splitter layout, display mode (IP/MAC), metric (Packets/Bytes), Top N, view (Circle/Table), and line thickness are saved to `~/.PacketCircle/settings.ini` and restored on next launch
- **Connection Popup** - Click a line in the circle to see a port-level connection summary with protocol, destination port, service name, and packet counts
- **Context Menu Filtering** - Right-click a row in the connection popup to apply a Wireshark display filter or follow a TCP stream
- **Search Blinking in Pair List** - Search results blink red/yellow in both the circle and the pair list simultaneously
- **Name Resolution** - Circle nodes and pair list display resolved names matching Wireshark's global name resolution settings
- **Modern Controls UI** - Redesigned toolbar with segmented button groups and icon-style action buttons
- **Responsive Layout** - Window scales from 640x480 to Full HD+; circle and node fonts resize proportionally
- **Version in Title Bar** - Plugin window title now shows the current version
- **Windows 10 Guidance** - Windows installer detects Windows 10 and provides targeted advice for common VC++ runtime and DLL loading issues

### Changed
- Minimum window size reduced to 640x480 for older displays
- Default window size set to 1280x780

### Fixed
- Search bar visibility on Windows (text was black on black background)
- Splitter handle now easier to grab on Windows
- AI-Assisted: yes (Claude) — UI development, preference persistence, connection popup, Windows compatibility, documentation

## [0.2.2] - 2026-02-13

### Added
- **Adaptive MAC Display** - MAC addresses in the pair list show abbreviated form when the panel is narrow and full address when the panel is wide enough
- **Multi-Version Linux Support** - Unified installer with pre-built binaries for Wireshark 4.2.x, 4.4.x, and 4.6.x
- **Smart Installer** - Linux installer auto-detects Wireshark version and installs the correct binary
- Source code uses conditional compilation to support Wireshark 4.2.x–4.6.x APIs
- AI-Assisted: yes (Claude) — build automation, installer scripting, cross-platform compatibility, documentation

### Changed
- Reduced font size on Windows for better cross-platform consistency

### Fixed
- Fixed protocol color mapping documentation to match actual implementation

## [0.2.1] - 2026-02-11

### Added
- **Universal Binary** - macOS plugin now runs natively on both Intel (x86_64) and Apple Silicon (arm64)
- **Linux x86_64 Binary** - Pre-built plugin for Linux (Ubuntu 24.04 / Debian-based)
- **Wireshark 4.6.x Compatibility** - Built against Wireshark 4.6.3 for broad 4.6.x support
- **PDF Report Export** - Generate a professional one-page PDF report with circle visualization, IP pair table, and summary
- **Clear Filter Button** - Quickly reset the Wireshark display filter and show all connections
- **Node Tooltips** - Hover over circle nodes to see destination ports, service names, and packet counts
- **Protocol Filtering** - Interactive checkboxes to filter the visualization by specific protocols
- **Mixed Protocol Visualization** - Dotted lines with alternating TCP/UDP colors for mixed-protocol connections
- **Search Filter** - Search box to quickly find IP addresses in the pair list
- **Directional Filtering** - Display filters now correctly match a single direction (A->B) instead of both directions
- **Resizable Splitter** - Drag the divider between the circle and pair list to resize panels
- **Help Dialog** - In-app help documenting all features and controls

### Changed
- Increased default window size to prevent button text clipping
- Circle visualization only shows selected pairs (non-selected pairs are completely hidden)
- PDF circle uses white background with high-contrast labels for print readability
- Improved control bar spacing and layout

### Fixed
- Fixed issue where selecting a single pair showed multiple lines on the circle
- Fixed bidirectional filter generation (was showing both A->B and B->A instead of just the selected direction)
- Fixed splitter between circle and pair list (was visible but non-functional)
- Fixed PDF table column widths to prevent "Bytes" label clipping
- Fixed installer script compatibility (POSIX printf, Wireshark version detection, plugin path discovery)
- Installer now checks Wireshark version and warns if not 4.6.x (prevents installing incompatible binary)

## [0.1.0] - 2025-12-01

### Initial Release
- Circle visualization of network communication pairs
- Protocol color coding (HTTP, HTTPS, SMB, DNS, MSSQL, SSH, FTP, TCP, UDP)
- Line weight proportional to traffic volume
- Top 10/25/50 conversation limits
- Packets and Bytes metric switching
- Circle and Table view modes
- MAC and IP address pair modes
- Wireshark display filter integration
- Select All / Select None bulk operations
- Protocol legend with color indicators
