# Graph View — Scoring Algorithms

This document explains how PacketCircle computes the **TCP Health** and **Anomaly Score**
for each edge in the Graph view.

> Scores are computed entirely from aggregate statistics stored per communication pair
> (byte count, packet count, destination port table, protocol identity, frame timestamps).
> Per-packet TCP flag counts (SYN, RST, FIN) are **not** accessible at this level.
> For flag-level analysis, click any edge → Connection Details → Transport Details.

---

## TCP Health Score

**Range:** 0% (very unhealthy) … 100% (healthy)  
**Baseline:** 50%  
**Color map:** Green ≥75% · Yellow 50–74% · Orange 28–49% · Red <28%

The score starts at 50% and is adjusted up or down by each of the following signals.
Only TCP pairs are scored; non-TCP pairs return a neutral 50%.

### Positive signals (connection looks healthy)

| Signal | Condition | Change |
|--------|-----------|--------|
| Large payload | Avg packet size > **800 B** | +25% |
| Moderate payload | Avg packet size > **300 B** | +15% |
| Small payload | Avg packet size > **100 B** | +5% |
| Identified protocol | Top protocol is not raw "TCP" (e.g. HTTPS, SSH) | +15% |
| Sustained connection | Packet count > **50** | +10% |

### Negative signals (connection looks unhealthy)

| Signal | Condition | Change |
|--------|-----------|--------|
| Tiny packets | Avg packet size < **80 B** — likely SYN/RST control only | −30% |
| No app protocol | Top protocol is raw "TCP" — handshake may have failed | −15% |
| Very few packets | Packet count < **4** — refused or half-open | −20% |
| Few packets | Packet count < **10** — brief or incomplete | −10% |
| High port diversity | Destination ports > **5** — unusual for a TCP session | −25% |
| Elevated port diversity | Destination ports > **2** — slightly unusual | −10% |

### Notes

- When both directions of a pair are available, the **lower** (worse) health score is used.
- Thresholds marked in **bold** are the defaults and can be adjusted in
  Settings → Graph Thresholds.

---

## Anomaly Score

**Range:** 0% (clean) … 100% (highly anomalous)  
**Baseline:** 0%  
**Color map:** Green ≤12% · Yellow 13–30% · Orange 31–55% · Red >55%

The score starts at 0% and increases for each detected signal.

### Port diversity (port scan indicators)

| Signal | Condition | Change |
|--------|-----------|--------|
| Critical diversity | Destination ports > **20** | +50% |
| High diversity | Destination ports > **10** | +35% |
| Elevated diversity | Destination ports > **5** | +20% |
| Slight diversity | Destination ports > **2** | +8% |

### Scan rate

| Signal | Condition | Change |
|--------|-----------|--------|
| Rapid scan | Ports > **3** and avg packets/port < **3.0** | +20% |

### Flood patterns

| Signal | Condition | Change |
|--------|-----------|--------|
| SYN flood | Avg packet size < **60 B** and packet count > **15** | +25% |
| Small-packet flood | Avg packet size < **100 B** and packet count > **30** | +10% |

### Raw TCP signals

| Signal | Condition | Change |
|--------|-----------|--------|
| Raw TCP multi-port | Protocol = "TCP" and destination ports > 1 | +15% |
| Raw TCP tiny packets | Protocol = "TCP" and avg packet size < 100 B | +10% |

### Legacy / insecure destination ports (fixed, not configurable)

| Port | Service | Change |
|------|---------|--------|
| 23 | Telnet — plaintext remote shell | +20% |
| 513 | rlogin — legacy insecure login | +15% |
| 514 | rsh — legacy insecure shell | +15% |
| 69 | TFTP — unauthenticated file transfer | +10% |

### Exfiltration indicator

| Signal | Condition | Change |
|--------|-----------|--------|
| One-way high-volume | No reverse direction and packet count > **100** | +15% |

### Notes

- When both directions of a pair are available, the **higher** (worse) anomaly score is used.
- Thresholds marked in **bold** are the defaults and can be adjusted in
  Settings → Graph Thresholds.

---

---

## TCP Window Mode

**Color map:** Green = healthy · Yellow = mild pressure · Orange = constrained · Red = zero-window stall

Colors edges by receiver-side TCP window pressure observed during the connection:

| Color | Condition |
|-------|-----------|
| Green | No zero-window events and average window > 64 KB |
| Yellow | Average window between 8 KB and 64 KB (mild back-pressure) |
| Orange | Average window below 8 KB (constrained — receiver buffer almost full) |
| Red | One or more zero-window events detected (full stall) |

Zero-window events and window sizes are extracted from `tcp.window_size_value` in the dissection tree. Only TCP connections are colored; non-TCP pairs remain grey.

---

## High Risk Mode

**Color map:** Grey = safe · Yellow = elevated · Orange = high · Red = critical · Violet = VPN/TOR

Colors edges by the highest-risk port observed on the connection. Risk levels are fixed and not configurable:

| Color | Risk Level | Ports / Protocols |
|-------|-----------|-------------------|
| Red — Critical | Cleartext shell or file transfer, trivially exploitable | Telnet (23), FTP/FTP-Data (21/20), rsh/rexec/rlogin (512–514), TFTP (69), native X11 (6000–6063), VNC (5900–5902) |
| Orange — High | Remote management with known CVE exposure | RDP (3389), WinRM (5985/5986), AnyDesk (7070) |
| Yellow — Elevated | Encrypted but sensitive or historically targeted | SSH (22), MQTT unencrypted (1883), SNMP (161/162) |
| Violet — VPN/TOR | Tunneling or anonymization infrastructure | OpenVPN (1194), WireGuard (51820), L2TP (1701), IKE/IPsec (500/4500), TOR (9001/9030/9050/9150) |
| Grey — Normal | All other traffic | — |

Hovering an edge in High Risk mode shows a tooltip listing each detected risk signal by name.

---

## Score Breakdown in the UI

In **TCP Health** or **Anomaly Score** edge color mode, click any edge to open the
Connection Details popup. A **Score** button appears in the popup header.
Click it to see a table listing every signal that fired, the direction of its effect,
and the exact percentage contribution.

For TCP connections the breakdown also shows **TCP Window statistics**: minimum, maximum,
and average receiver window size (bytes), the number of zero-window events observed,
and the maximum zero-window stall duration (ms). These values are the same ones used to
color the edge in **TCP Window** mode and help diagnose receiver-side bottlenecks alongside
the health score signals.

---

## Threshold Groups

Default thresholds are designed for typical enterprise/datacenter traffic.
You can create custom groups in **Settings → Graph Thresholds** to tune sensitivity
for different environments:

- **Strict (production)** — lower port diversity thresholds, smaller packet size bins
- **Relaxed (lab/dev)** — higher flood packet counts, more ports tolerated
- **IoT / embedded** — smaller packet sizes expected, fewer ports normal

Select the active group from the Settings drop-down. The graph recomputes scores
and re-colors edges immediately.
