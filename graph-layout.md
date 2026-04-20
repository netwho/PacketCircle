# PacketCircle Graph Layouts

PacketCircle offers eight graph layout algorithms for the Graph View. Each arranges nodes (hosts) and edges (traffic pairs) differently, making particular patterns in your capture easier to spot. This document describes how each layout works and when to use it.

---

## Node and Edge fundamentals

Every host in the capture becomes a **node**. Its size scales logarithmically with total traffic volume (bytes or packets). Every conversation between two hosts becomes an **edge**, whose thickness and colour encode the selected edge metric (protocol, TCP health, anomaly score, response time, throughput, or risk).

**Node colour** is set independently of layout via the Node Colour selector (Service, Role, Protocol, Function). Some layouts adapt their grouping logic to the active node colour mode — see Cluster below.

---

## Layout reference

### 1. Force

> *Fruchterman-Reingold force-directed placement*

Nodes repel each other like charged particles and edges attract their endpoints like springs. A weak gravity pulls everything toward the centre so isolated clusters don't drift off screen. Attraction along each edge is weighted by byte volume, so heavily-used connections pull their endpoints closer together.

The algorithm runs 150 cooling iterations. Positions are seeded deterministically from each host's address so the layout is reproducible across reloads with the same capture.

**What it reveals:** Natural traffic clusters emerge without any prior knowledge — hosts that talk a lot end up near each other. Isolated or peripheral hosts float to the edges. Tight cliques (e.g. an application server and its database) collapse into a dense cluster; internet breakout nodes sit in the middle connecting internal and external halves.

**Best for:** Exploratory analysis of an unfamiliar capture. Good first layout to try.

---

### 2. Star

> *Busiest node at centre, all others on concentric rings*

The node with the highest connection count (degree) is placed at the centre. All remaining nodes are arranged on one or more concentric rings at equal angular spacing. If there are more nodes than fit on the inner ring, they overflow onto a second ring at a larger radius, and so on.

**What it reveals:** Immediately identifies the most-connected host — typically a gateway, domain controller, DNS server, or any hub-and-spoke infrastructure element. All spokes radiate from the same point, making it easy to see which hosts communicate only with the hub versus which have lateral connections.

**Best for:** Captures with a clear hub (corporate gateway, DNS resolver, DHCP server). Less useful when traffic is peer-to-peer or distributed.

---

### 3. Circular

> *Equal angular spacing on a single ring, largest node at top*

All hosts are placed on a circle at equal angular intervals. Nodes are sorted by total byte volume descending, so the highest-traffic host appears at the 12 o'clock position and the rest follow clockwise.

**What it reveals:** Edge crossings show how interconnected the hosts are. A capture with a dominant server will show many edges converging on the top node with few lateral edges. A fully meshed network produces a dense web of crossings. The sorted order makes traffic ranking immediately visible by position.

**Best for:** Comparing relative traffic volumes across all hosts. Similar to the Circle View but without the arc-chord encoding — good when you want the raw graph view without switching modes.

---

### 4. Grid

> *Deterministic grid, highest-traffic nodes in the top-left*

Nodes are arranged in a roughly square grid sized to the window aspect ratio. Sorting is by total bytes descending, so the busiest hosts occupy the top-left cells and the quietest hosts fill the bottom-right.

**What it reveals:** A structured, non-overlapping layout useful when you want to see every node simultaneously without any spatial bias from traffic patterns. Edge density across the grid shows which areas of your address space are most interconnected.

**Best for:** Inventorying all observed hosts. Useful as a starting point when you need to locate a specific host visually without knowing its traffic rank.

---

### 5. Cluster

> *Grouped by a context-sensitive key, with labelled background blobs*

Nodes are grouped into named clusters. Each cluster is rendered as a coloured background blob with a label. Nodes within a cluster are arranged in a mini-circle inside their blob. Cluster blobs are spread across the canvas on a larger circle (or grid when there are many clusters).

The grouping key adapts to the active **Node Colour** mode:

| Node Colour mode | Cluster key |
|---|---|
| **Role** | Network role: each RFC 1918 subnet gets its own sub-blob (e.g. `192.168.1.x`, `10.0.x`) nested inside a larger "Internal" super-blob. External, Broadcast, and MAC hosts each get their own blob. |
| **Service** | Dominant service/port on each host (e.g. HTTPS, SMB, DNS). Hosts that mostly serve or use the same port are grouped together. |
| **Protocol** | Dominant L7 protocol across all of a host's connections (e.g. TLS, HTTP, DNS). |
| **Function** | Service category: Remote Access (RDP/VNC/Citrix), Interactive Shell (SSH/Telnet), Messaging (SIP/XMPP/IRC), File Transfer (SMB/NFS/FTP), Other. |
| WiFi mode | 802.11 frame role: Access Point, Management, Data, Broadcast. |

**Role mode — nested blobs:** The "Internal" super-cluster wraps all RFC 1918 sub-blobs inside one large blue background. Each private range (10.x, 172.16–31.x, 192.168.x) gets its own sub-blob in a distinct colour (amber, green, teal). The `/bits` clustering granularity is configurable per subnet in Settings → Internal Networks.

**What it reveals:** Structural groupings that are invisible in free-form layouts. In Role mode you immediately see internal subnet segmentation and which external hosts bridge into the internal network. In Service or Protocol mode you see which hosts provide similar services and whether cross-cluster traffic (e.g. a client cluster talking to an unexpected server cluster) exists.

**Best for:** Segmentation analysis, subnet mapping, service inventory, and WiFi frame-type breakdown. The most information-dense layout when combined with the matching node colour mode.

---

### 6. Concentric

> *Concentric rings sorted by connection degree*

Nodes are sorted by their connection count (degree) descending. If the most-connected node has at least twice the degree of the second-most-connected, it is placed alone at the centre. Otherwise placement starts at the innermost ring. Subsequent rings are added outward, each holding as many nodes as fit at a readable angular spacing (~70 px per node).

**What it reveals:** A clean hierarchy of connectivity — the innermost ring is your infrastructure (gateways, DNS, AD), middle rings are servers and services, the outermost ring is endpoints and clients. Lateral edges (between nodes on the same ring) indicate peer-to-peer or east-west traffic that bypasses the hub.

**Best for:** Distinguishing infrastructure hosts from end-user endpoints. Good for spotting lateral movement — unexpected connections between outer-ring hosts that should only talk to the core.

---

### 7. Hierarchical

> *Four tiers: External → Gateway → Server → Client*

Nodes are classified into four tiers and arranged in horizontal rows from top to bottom:

| Tier | Label | Classification logic |
|---|---|---|
| 0 (top) | **External / Internet** | Non-RFC 1918 addresses |
| 1 | **Gateway** | RFC 1918 hosts with edges to both external and internal addresses |
| 2 | **Internal Server** | RFC 1918 hosts accepting connections on well-known ports (< 1024) |
| 3 (bottom) | **Client** | All remaining internal hosts |

Within each tier, nodes are sorted left-to-right by total bytes descending. Empty tiers are collapsed so available vertical space is shared evenly across populated tiers.

**What it reveals:** The classic network perimeter model — internet at the top, clients at the bottom, with firewalls/gateways and servers in between. Edges that skip tiers (e.g. direct external-to-client) are immediately visible as long diagonal lines crossing tier boundaries, flagging potential policy violations or compromised hosts.

**Best for:** Perimeter and segmentation review. East-west server-to-server traffic appears as horizontal edges in tier 2; internet-to-client direct paths appear as long vertical edges bypassing tier 1.

---

### 8. Radial

> *BFS rings outward from the most-connected node*

The node with the highest degree is placed at the centre. A breadth-first search expands outward: nodes at BFS depth 1 form the first ring, depth 2 the second ring, and so on. Nodes unreachable from the root (isolated sub-graphs) are placed in the outermost ring.

Unlike Star, which places everything by degree alone, Radial preserves the actual graph distance from the root — nodes that are topologically close appear in inner rings regardless of their own degree.

**What it reveals:** Influence distance from the most-connected host. A direct partner of the gateway is on ring 1; a host that only talks to ring-1 hosts lands on ring 2, even if it has many connections. This makes lateral reach easy to see: a compromised host on ring 1 that suddenly has ring-3 hosts connecting to it will show those edges as inward-pointing spokes cutting across rings.

**Best for:** Mapping blast radius or reachability from a specific host. Complement to Concentric — use Concentric to rank hubs by degree, then switch to Radial to see actual graph distance from the top hub.

---

## Choosing a layout

| Goal | Recommended layout |
|---|---|
| First look at an unfamiliar capture | Force |
| Find the dominant gateway or hub | Star or Concentric |
| Map subnets and segmentation | Cluster (Role mode) |
| Group by service or protocol | Cluster (Service or Protocol mode) |
| Perimeter / firewall review | Hierarchical |
| Inventory all hosts without bias | Grid |
| Compare traffic volume across hosts | Circular |
| Measure reachability from a hub | Radial |

---

## Interaction notes

- **Drag nodes** to adjust positions within any layout. Positions are preserved until you explicitly switch layout or click Relayout.
- **Ctrl + drag a cluster blob** (Cluster layout) to reposition the whole group.
- **Lock Positions** (toolbar) freezes node positions so live capture updates don't re-run the layout algorithm.
- **Node Colour** and **Layout** are independent — you can combine any colour mode with any layout. The Cluster layout adapts its grouping to the active colour mode; all other layouts are unaffected by it.
