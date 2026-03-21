# PacketCircle — Protocol Information Reference

PacketCircle provides deep protocol inspection dialogs accessible by right-clicking a connection row in the **Connection Details** popup. Each dialog extracts information directly from Wireshark's packet dissection engine and shows data filtered to the **selected pair only**.

---

## How to Access Protocol Info

1. Open a capture in Wireshark
2. Launch PacketCircle via **Tools → PacketCircle**
3. Click a connection line in the circle, or select a pair in the pair list
4. In the **Connection Details** popup, right-click a row
5. Select the relevant protocol info option from the context menu

Protocol info options are enabled/disabled based on the destination port of the selected row. Unavailable options are shown greyed out with the required port in parentheses.

---

## IP Mode Protocols

### TLS / SSL Information
**Trigger:** Port 443 (HTTPS), or any TCP connection using TLS
**Available in:** IP mode

| Section | Details |
|---|---|
| Session Overview | TLS version, cipher suite, ALPN, SNI (Server Name Indication) |
| JA3 / JA4 | Client and server fingerprints for threat detection |
| Certificate Chain | Subject, issuer, validity (not-before / not-after), Subject Alternative Names (SANs) |
| Handshake Stats | Handshake count, session reuse, alert messages |
| Traffic Summary | Matched packet count |

---

### HTTP Information
**Trigger:** Port 80, or any TCP connection with HTTP traffic
**Available in:** IP mode

| Section | Details |
|---|---|
| Request Methods | GET, POST, PUT, DELETE, HEAD, OPTIONS counts |
| Status Codes | 2xx, 3xx, 4xx, 5xx breakdown with individual code counts |
| URIs | List of requested URIs with method and status |
| Hosts / Virtual Hosts | HTTP Host header values seen |
| Server Headers | Server software identifiers |
| Content Types | MIME types of responses |
| User Agents | Client software strings |
| Cookies | Cookie names observed (values redacted) |

---

### SMB / CIFS & DCE/RPC Information
**Trigger:** Ports 445 (SMB direct), 135 (DCE-RPC endpoint mapper)
**Available in:** IP mode

| Section | Details |
|---|---|
| SMB Dialect | Negotiated SMB version (SMB1 / SMB2 / SMB3) |
| Tree Operations | Share names accessed (UNC paths) |
| File Operations | File open/read/write/close/delete counts per share |
| Named Pipes | Pipe names accessed |
| DCE/RPC Interfaces | Interface UUIDs with resolved names (SAMR, LSARPC, SVCCTL, etc.) |
| RPC Operations | Operation names and call counts per interface |
| Authentication | NTLM / Kerberos authentication events |

---

### Kerberos Information
**Trigger:** Port 88
**Available in:** IP mode

| Section | Details |
|---|---|
| Ticket Types | TGT (AS-REQ/AS-REP) and TGS (TGS-REQ/TGS-REP) counts |
| Client Principals | Kerberos client names (cname) |
| Server Principals | Service Principal Names (SPN) |
| Realms | Kerberos realm names |
| Encryption Types | etypes used in requests and responses |
| Pre-Authentication | PA-DATA types (PA-ENC-TIMESTAMP, PKINIT, etc.) |
| Error Codes | KRB5KDC_ERR_* and KRB5KRB_AP_ERR_* errors |

---

### Email Information (SMTP / IMAP / POP3)
**Trigger:** Ports 25, 587, 465 (SMTP), 143, 993 (IMAP), 110, 995 (POP3)
**Available in:** IP mode

| Section | Details |
|---|---|
| SMTP | MAIL FROM / RCPT TO addresses, subjects, server banners, AUTH methods |
| IMAP | LOGIN commands, SELECT/EXAMINE mailbox names, FETCH/STORE operations |
| POP3 | USER commands, STAT/LIST/RETR/DELE operation counts |
| Authentication | AUTH mechanisms (PLAIN, LOGIN, CRAM-MD5, OAUTH2) |
| TLS Upgrade | STARTTLS detection |

---

### SQL Database Information
**Trigger:** Port 1433 (MSSQL), 3306 (MySQL), 5432 (PostgreSQL)
**Available in:** IP mode

| Section | Details |
|---|---|
| Server Info | Server version string, database/schema name, application name |
| Authentication | Login names, authentication method |
| Queries | SQL statements captured (SELECT, INSERT, UPDATE, DELETE, CREATE, etc.) |
| Errors | SQL error codes and messages |
| Statistics | Command counts, response counts, error rate |

---

### VoIP / SIP Information
**Trigger:** Ports 5060, 5061
**Available in:** IP mode

| Section | Details |
|---|---|
| SIP Calls | Call-IDs observed |
| SIP Methods | INVITE, BYE, ACK, REGISTER, OPTIONS, CANCEL counts |
| SIP Status Codes | 1xx, 2xx, 3xx, 4xx, 5xx response breakdown |
| Addresses | From / To SIP URIs |
| User Agents | SIP UA strings |
| RTP | Payload types (PCMU, PCMA, G.729, G.722, opus, H.264, …), SSRCs |
| RTP Setup | Via SDP / STUN / ICE |
| H.223 Mux | H.223 multiplex entries (video conferencing) |

---

### DHCP / BOOTP Information
**Trigger:** Ports 67 / 68
**Available in:** IP mode

| Section | Details |
|---|---|
| Message Types | DISCOVER, OFFER, REQUEST, ACK, NAK, RELEASE, INFORM counts |
| Leases | Client MAC → assigned IP mappings |
| DHCP Options | Subnet mask, default gateway, DNS servers, lease time, domain name |
| Server | DHCP server IP address |
| Client IDs | Hardware addresses and client identifiers |

---

### DNS Information
**Trigger:** Port 53 (DNS), Port 5353 (mDNS)
**Available in:** IP mode
*(new in v0.4.2)*

| Section | Details |
|---|---|
| Traffic Summary | Total DNS packets, query count, response count, recursion desired, DNS-over-TCP |
| Response Codes | NOERROR, NXDOMAIN, SERVFAIL, REFUSED, other error counts |
| Query Types | A, AAAA, CNAME, MX, NS, PTR, TXT, SRV, DS, RRSIG, DNSKEY, HTTPS, CAA, ANY counts |
| Queried Domains | Domain names queried with per-name counts (top 50 shown) |
| Resolved Answers | Answer records in format `name TYPE value` (A/AAAA/CNAME/MX/NS/PTR/TXT/SRV/SOA/CAA) |
| NXDOMAIN Names | Names that received NXDOMAIN responses |

---

### LDAP / LDAPS Information
**Trigger:** Ports 389, 636 (LDAPS), 3268, 3269 (Global Catalog)
**Available in:** IP mode

| Section | Details |
|---|---|
| Session Summary | Matched packet count, bind requests, bind results |
| Bind / Authentication | Bind DNs, SASL mechanisms, simple vs. SASL auth |
| Search Operations | Base DNs, scope (base/one/sub), filter strings, attribute requests |
| Modify / Add / Delete | Operation counts per type |
| Result Codes | success, noSuchObject, invalidCredentials, unwillingToPerform, etc. |
| Controls | Request/response control OIDs (paging, sorting, VLV, etc.) |

---

### SNMP Information
**Trigger:** Ports 161 (SNMP), 162 (SNMP Trap)
**Available in:** IP mode

| Section | Details |
|---|---|
| Session Summary | Matched packet count, SNMP version (v1 / v2c / v3) |
| Community Strings | Community names seen (v1/v2c) |
| PDU Types | GetRequest, GetNextRequest, GetBulk, SetRequest, Response, Trap, InformRequest counts |
| OIDs | Object identifiers queried or reported |
| Trap Info | Trap enterprise OID, generic trap type, specific trap code |
| Errors | Error status codes and error indices |

---

### Syslog Information
**Trigger:** Ports 514 UDP/TCP (classic Syslog), 601 TCP (RFC 5425), 6514 TLS
**Available in:** IP mode

| Section | Details |
|---|---|
| Session Summary | Matched packet count, transports (UDP / TCP / TLS) |
| Severity Breakdown | Emergency, Alert, Critical, Error, Warning, Notice, Informational, Debug counts |
| Facility Breakdown | kern, user, mail, daemon, auth, syslog, lpr, news, uucp, cron, local0–7 |
| Recent Messages | Last messages captured (up to 20), with timestamp, severity, facility, and message text |

---

### SSH / SFTP / SCP Information
**Trigger:** Port 22
**Available in:** IP mode

| Section | Details |
|---|---|
| Session Summary | Matched packet count, key exchange count, new keys count |
| Key Exchange | Algorithm negotiation (kex algorithms, host key algorithms) |
| Encryption | Cipher and MAC algorithm pairs for client→server and server→client |
| Compression | Compression algorithms negotiated |
| Channels | Channel open/close counts, channel type (session, direct-tcpip, forwarded-tcpip) |
| Protocol Note | SSH payloads are encrypted; only handshake metadata is visible |

---

### FTP Information
**Trigger:** Ports 21 (control), 20 (active data), 990 (FTPS implicit)
**Available in:** IP mode

| Section | Details |
|---|---|
| Session Summary | Auth result (success/failure), login credentials (username/password in cleartext), data transfer mode (PASV / PORT) |
| Server Features | FEAT response capabilities |
| Data Ports Negotiated | PASV and PORT addresses/ports used for data connections |
| Command Usage | All FTP commands with counts, sorted by frequency (PASS highlighted in red) |
| Files / Paths | Filenames and paths seen in RETR, STOR, NLST, LIST commands |
| Command Log | Chronological command log (up to 200 entries) |

> **⚠ Security note:** FTP transmits credentials in cleartext. Username and password are visible if present in the capture.

---

### Telnet Information
**Trigger:** Ports 23, 992 (Telnet over TLS)
**Available in:** IP mode

| Section | Details |
|---|---|
| Session Summary | Matched packet count, total data bytes, detected credentials |
| Option Negotiations | WILL / DO (green) and WONT / DONT (amber) option tables |
| Capabilities Detected | Echo, Linemode, NAWS (window size), Terminal Type, Authentication, Encryption options |
| Session Data | Reassembled Telnet payload (up to 1 KB), monospace scrollable block |

> **⚠ Security note:** Telnet transmits all data including credentials in plaintext.

---

### NBNS — NetBIOS Name Service
**Trigger:** Port 137 UDP
**Available in:** IP mode

| Section | Details |
|---|---|
| Session Summary | Matched packet count, query count, response count, registration / release / WACK / refresh counts |
| Name Resolution | Name → IP mapping table from all responses, with operation type |

> **Note:** NBNS provides name registration and resolution for legacy Windows networking. Modern environments use DNS instead.

---

### NetBIOS Datagram Service
**Trigger:** Port 138 UDP
**Available in:** IP mode

| Section | Details |
|---|---|
| Session Summary | Matched packet count, Direct Unique / Direct Group / Broadcast / Error datagram counts |
| Datagram Types | Per-type breakdown (Direct Unique, Direct Group, Broadcast, Query Request, etc.) |
| Source Names | Source NetBIOS names with packet counts |
| Destination Names | Destination NetBIOS names with packet counts |

> **Note:** Port 138 carries Windows browser announcements, domain master browser elections, and SMB browse-list traffic.

---

### NetBIOS Session Service (NBSS)
**Trigger:** Port 139 TCP
**Available in:** IP mode

| Section | Details |
|---|---|
| Session Summary | Matched packet count, session requests, confirmed, rejected, keepalives, session messages |
| Session Setup | Calling name (client) → Called name (server) pairs from session request packets |

> **Note:** Port 139 TCP is the legacy NetBIOS Session transport for SMB. Modern SMB uses port 445 directly. Right-click a port 445 connection for full SMB protocol details.

---

### TCP Transport Details
**Trigger:** Any TCP connection (right-click → "TCP Transport Details…")
**Available in:** IP mode
*(new in v0.4.6)*

| Section | Details |
|---|---|
| TCP Flags | Flags observed across all packets: SYN, ACK, FIN, RST, PSH, URG, ECE, CWR — shown as colour-coded pills |
| Window Size | Min / max / average TCP window size (bytes) |
| MSS | Maximum Segment Size from SYN options |
| Negotiated Options | SACK Permitted, Timestamps, Window Scale (with multiplier value) |
| RTT | Min / max / average round-trip time in ms, derived from `tcp.analysis.ack_rtt` |
| Retransmissions | Retransmission packet count |
| Out-of-Order | Out-of-order packet count |

> Available on every TCP connection alongside any port-specific application-layer dialog (e.g. HTTP Info + TCP Transport Details for port 80).

---

### UDP Transport Details
**Trigger:** Any UDP connection (right-click → "UDP Transport Details…")
**Available in:** IP mode
*(new in v0.4.6)*

| Section | Details |
|---|---|
| Payload Size | Min / max / average datagram payload bytes (derived from `udp.length − 8`) |
| Direction Breakdown | A→B and B→A packet counts with percentages and an ASCII asymmetry bar |
| Datagram Notes | Fixed-size detection (all datagrams identical size); fragmentation risk warning for datagrams > 1472 bytes |

---

## MAC Mode Protocols

In MAC mode, PacketCircle visualizes Ethernet-level (Layer 2) communication pairs. The following protocols have dedicated information available.

### Layer-2 Frame Details (all MAC-mode pairs)
**Trigger:** Any pair in MAC mode (right-click → "Layer-2 Frame Details")
**Available in:** MAC mode

| Section | Details |
|---|---|
| EtherType(s) | Hex EtherType values with protocol names and frame counts (e.g. 0x0806 ARP × 47) |
| VLAN IDs | 802.1Q VLAN tag values seen |
| LLC/SAP | DSAP/SSAP values with protocol interpretation |
| SNAP | SNAP OUI and protocol type |
| Frame Stats | Total frame count, byte count |

---

### ARP — MAC/IP Mapping
**Trigger:** ARP pairs in MAC mode (right-click → "ARP MAC/IP Mapping")
**Available in:** MAC mode

| Section | Details |
|---|---|
| ARP Requests | Who-has queries with target IP |
| ARP Replies | Is-at responses with MAC → IP bindings |
| Gratuitous ARP | Unsolicited ARP announcements |
| ARP Spoofing Hints | Multiple MACs claiming the same IP |

---

### STP — Spanning Tree Information
**Trigger:** STP/RSTP/MSTP/PVST pairs (right-click → "STP Information")
**Available in:** MAC mode

| Section | Details |
|---|---|
| STP Version | STP / RSTP / MSTP / PVST+ |
| Root Bridge | Root Bridge ID (priority + MAC) |
| Root Path Cost | Advertised cost to root |
| Port States | Designated port, port ID, port role |
| BPDU Types | Configuration BPDU, TCN, Rapid BPDU counts |
| Topology Changes | TC flag count (network reconvergence events) |

---

### LLDP — Link Layer Discovery
**Trigger:** LLDP pairs (right-click → "LLDP Information")
**Available in:** MAC mode

| Section | Details |
|---|---|
| Chassis ID | Chassis identifier (MAC or IP) |
| Port ID | Port identifier string |
| System Name | Advertised device hostname |
| System Description | OS and platform information |
| Capabilities | Router, Switch, Bridge, AP, etc. |
| Management Address | IP address for management |
| LLDP-MED | Media endpoint device type, network policy, PoE information |
| TTL | Time-to-live of the LLDP frame |

---

### LACP — Link Aggregation
**Trigger:** LACP pairs (right-click → "LACP Information")
**Available in:** MAC mode

| Section | Details |
|---|---|
| Actor | Actor system MAC, key, port, state flags |
| Partner | Partner system MAC, key, port, state flags |
| State Flags | LACP_Activity, LACP_Timeout, Aggregation, Synchronization, Collecting, Distributing |
| PDU Counts | LACP PDU and Marker PDU counts |

---

### EAP / 802.1X — Port Authentication
**Trigger:** EAPOL pairs (right-click → "EAP/802.1X Information")
**Available in:** MAC mode

| Section | Details |
|---|---|
| EAP Methods | EAP-TLS, EAP-PEAP, EAP-TTLS, EAP-MD5, EAP-MSCHAPv2 |
| Authentication Result | Success / Failure |
| Identity | EAP Identity response value |
| Frame Types | EAPOL-Start, EAPOL-Logoff, EAP-Request, EAP-Response counts |

---

### VLAN — IEEE 802.1Q
**Trigger:** `0x8100` rows in MAC mode (right-click → "VLAN (802.1Q) Information")
**Available in:** MAC mode
*(new in v0.4.3)*

| Section | Details |
|---|---|
| Summary | Total matched frames, QinQ (double-tagged) frame count, DEI/CFI bit count |
| VLAN IDs | VLAN ID → frame count, sorted by frame count descending |
| PCP Distribution | Per-priority frame count with IEEE 802.1p class names (Best Effort, Background, Excellent Effort, Critical Applications, Video, Voice, Internetwork Control, Network Control) |

---

### MACsec — IEEE 802.1AE
**Trigger:** MACsec pairs / `0x88E5` rows (right-click → "MACsec Information")
**Available in:** MAC mode

| Section | Details |
|---|---|
| Overview | Matched frame count, encryption E-bit status, SC-bit (SCI present), SecTAG decoded/fallback note |
| Association Numbers | Per-AN (0–3) frame count table |
| Packet Numbers | PN min / max range across observed frames |
| SCI Values | Secure Channel Identifiers in `AA:BB:CC:DD:EE:FF/PORT` format |

> **Note:** If the Wireshark MACsec dissector is inactive, SecTAG fields are parsed directly from raw packet bytes (TVB fallback). All fields above are populated via the fallback when the dissector is not available.

---

## Wi-Fi Mode

In Wi-Fi mode (802.11 monitor captures), PacketCircle shows a separate signal-quality view. Clicking any node opens a **Wi-Fi Station Detail** popup with:

| Section | Details |
|---|---|
| Identity | SSID, BSSID, station MAC |
| Radio | Channel, frequency band, 802.11 standard (a/b/g/n/ac/ax) |
| Signal Quality | Average RSSI, min/max RSSI, sample count, quality category |
| Traffic | Frame count, byte count |
| Frame Types | Management / Control / Data frame breakdown |
| Management Events | Probe Request/Response, Auth, Assoc, Deauth, Disassoc counts |

---

## Notes

- All protocol info dialogs filter data to the **selected pair** (source/destination IP addresses and port). They do not scan the entire capture.
- Dialogs are read-only and do not modify the capture.
- Some fields may not appear if the relevant packets were not captured or dissected by Wireshark (e.g. if a display filter is active, or if the capture started mid-session).
- Protocol info is extracted from Wireshark's native dissection — no third-party parsers are used.
