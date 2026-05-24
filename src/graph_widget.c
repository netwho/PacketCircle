/*
 * PacketCircle - Wireshark Network Communication Visualization Plugin
 *
 * Copyright (C) 2026 Walter Hofstetter
 * https://github.com/netwho/PacketCircle
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#include "graph_widget.h"
#include <QPainter>
#include <QPainterPath>
#include <QMouseEvent>
#include <QResizeEvent>
#include <QToolTip>
#include <QtMath>
#include <QDebug>
#include <QLocale>
#include <QFont>
#include <QFontMetrics>
#include <QQueue>
#include <QRandomGenerator>

/* ─────────────────────────────────────────────────────────────────────── *
 *  Service / port colour table
 *  Top-N ports get visually distinct colours; unknown → grey.
 * ─────────────────────────────────────────────────────────────────────── */
static QColor portServiceColor(quint16 port)
{
    switch (port) {
        case 20: case 21:
            return QColor(26, 188, 156);   /* FTP        teal        */
        case 22:
            return QColor(243, 156,  18);  /* SSH        amber       */
        case 23:
            return QColor(241, 196,  15);  /* Telnet     yellow      */
        case 25: case 465: case 587:
            return QColor(149, 165, 166);  /* SMTP       silver      */
        case 53:
            return QColor(142,  68, 173);  /* DNS        purple      */
        case 67: case 68:
            return QColor( 52, 152, 219);  /* DHCP       light blue  */
        case 80: case 8080: case 8000: case 8008:
            return QColor( 41, 128, 185);  /* HTTP       blue        */
        case 88:
            return QColor(155,  89, 182);  /* Kerberos   violet      */
        case 110: case 143: case 993: case 995:
            return QColor(230, 126,  34);  /* Email      orange      */
        case 123:
            return QColor( 26, 188, 156);  /* NTP        teal        */
        case 135: case 445: case 139:
            return QColor(231,  76,  60);  /* SMB/RPC    red         */
        case 161: case 162:
            return QColor( 44,  62,  80);  /* SNMP       dark slate  */
        case 179:
            return QColor( 52,  73,  94);  /* BGP        dark blue   */
        case 389: case 636:
            return QColor(211,  84,   0);  /* LDAP       dark orange */
        case 443: case 8443:
            return QColor( 39, 174,  96);  /* HTTPS      green       */
        case 514:
            return QColor(127, 140, 141);  /* Syslog     grey        */
        case 1433: case 1521:
            return QColor( 22, 160, 133);  /* SQL Server dark teal   */
        case 3306:
            return QColor(230,  81,   0);  /* MySQL      deep orange */
        case 3389:
            return QColor(192,  57,  43);  /* RDP        dark red    */
        case 5060: case 5061:
            return QColor(189, 195, 199);  /* SIP        light grey  */
        case 5432:
            return QColor( 41,  98, 163);  /* PostgreSQL dark blue   */
        case 5900:
            return QColor(174, 214,  41);  /* VNC        lime        */
        default:
            return QColor(120, 120, 120);  /* Unknown    grey        */
    }
}

/* Service name lookup — mirrors portToServiceName() in circle_widget.c */
static QString graphPortServiceName(quint16 port)
{
    switch (port) {
        case 20:   return "FTP-Data";
        case 21:   return "FTP";
        case 22:   return "SSH";
        case 23:   return "Telnet";
        case 25:   return "SMTP";
        case 53:   return "DNS";
        case 67: case 68: return "DHCP";
        case 69:   return "TFTP";
        case 80:   return "HTTP";
        case 88:   return "Kerberos";
        case 110:  return "POP3";
        case 111:  return "RPC";
        case 123:  return "NTP";
        case 135:  return "MS-RPC";
        case 137:  return "NetBIOS-NS";
        case 138:  return "NetBIOS-DGM";
        case 139:  return "NetBIOS-SSN";
        case 143:  return "IMAP";
        case 161:  return "SNMP";
        case 162:  return "SNMP-Trap";
        case 179:  return "BGP";
        case 389:  return "LDAP";
        case 443:  return "HTTPS";
        case 445:  return "SMB";
        case 465:  return "SMTPS";
        case 514:  return "Syslog";
        case 587:  return "SMTP-Sub";
        case 636:  return "LDAPS";
        case 993:  return "IMAPS";
        case 995:  return "POP3S";
        case 1433: return "MSSQL";
        case 1521: return "Oracle";
        case 2049: return "NFS";
        case 3306: return "MySQL";
        case 3389: return "RDP";
        case 5060: return "SIP";
        case 5061: return "SIPS";
        case 5432: return "PostgreSQL";
        case 5900: return "VNC";
        case 8080: return "HTTP-Proxy";
        case 8443: return "HTTPS-Alt";
        default:   return QString();
    }
}

/* Classify an address into a cluster key string.
 * Used by LAYOUT_CLUSTER when node colour mode is Service/Port, Protocol, or default. */
QString GraphWidget::subnetKeyFromParts(int a, int b, int c, int d, int bits)
{
    if (bits <= 8)  return QString("%1.x.x.x").arg(a);
    if (bits <= 16) return QString("%1.%2.x.x").arg(a).arg(b);
    if (bits <= 24) return QString("%1.%2.%3.x").arg(a).arg(b).arg(c);
    return QString("%1.%2.%3.%4").arg(a).arg(b).arg(c).arg(d);
}

QString GraphWidget::clusterKeyForAddr(const QString &addr) const
{
    if (addr.count(':') == 5 && addr.length() == 17)
        return QStringLiteral("MAC");
    if (addr.contains(':'))
        return QStringLiteral("IPv6");

    QStringList parts = addr.split('.');
    if (parts.size() != 4) return QStringLiteral("Other");
    bool ok1, ok2, ok3, ok4;
    int a = parts[0].toInt(&ok1);
    int b = parts[1].toInt(&ok2);
    int c = parts[2].toInt(&ok3);
    int d = parts[3].toInt(&ok4);
    if (!ok1||!ok2||!ok3||!ok4) return QStringLiteral("Other");

    if (a == 127)                        return QStringLiteral("127.x (Loopback)");
    if (a == 169 && b == 254)            return QStringLiteral("169.254.x (Link-Local)");
    if (a >= 224 && a <= 239)            return QStringLiteral("Multicast");
    if (addr == QStringLiteral("255.255.255.255")) return QStringLiteral("Broadcast");

    /* Check configured internal subnets for prefix-based grouping */
    quint32 addr32 = ((quint32)a << 24)|((quint32)b << 16)|((quint32)c << 8)|(quint32)d;
    for (const InternalSubnet &sn : m_internalSubnets) {
        QStringList pp = sn.prefix.split('.');
        if (pp.size() != 4) continue;
        bool pok[4]; int pv[4];
        for (int i = 0; i < 4; i++) pv[i] = pp[i].toInt(&pok[i]);
        if (!pok[0]||!pok[1]||!pok[2]||!pok[3]) continue;
        quint32 net  = ((quint32)pv[0]<<24)|((quint32)pv[1]<<16)|((quint32)pv[2]<<8)|(quint32)pv[3];
        /* Detect RFC1918 containment: use wider built-in mask for matching */
        quint32 detectBits = sn.bits;
        if (sn.builtIn) {
            if (pv[0] == 10)                             detectBits = 8;
            else if (pv[0] == 172)                       detectBits = 12;
            else if (pv[0] == 192 && pv[1] == 168)      detectBits = 16;
        }
        quint32 detectMask = detectBits > 0 ? (~0u << (32 - detectBits)) : 0;
        if ((addr32 & detectMask) == (net & detectMask))
            return subnetKeyFromParts(a, b, c, d, sn.bits);
    }

    return QStringLiteral("External");
}

QList<GraphWidget::InternalSubnet> GraphWidget::defaultInternalSubnets()
{
    QList<InternalSubnet> list;
    list.append({"10.0.0.0",     24, true});  /* Class A private */
    list.append({"172.16.0.0",   24, true});  /* Class B private */
    list.append({"192.168.0.0",  24, true});  /* Class C private */
    return list;
}

void GraphWidget::setInternalSubnets(const QList<InternalSubnet> &subnets)
{
    m_internalSubnets = subnets;
    if (m_layoutMode == LAYOUT_CLUSTER)
        applyLayout();
    else
        update();
}

/* WiFi cluster: classify a node by its dominant 802.11 frame type.
 *
 * Priority (highest first):
 *   Broadcast/Multicast  — multicast MAC (LSB of first octet set, or ff:ff:…)
 *   Access Point         — any pair from this node has beacon_count > 0
 *   Management           — mgmt_frame_count dominates across all pairs
 *   Data                 — data_frame_count dominates
 */
QString GraphWidget::wifiClusterKey(int nodeIdx) const
{
    const QString &addr = m_nodes[nodeIdx].rawAddr;

    /* Broadcast / Multicast: ff:ff:ff:ff:ff:ff or LSB of first octet = 1 */
    if (addr.length() >= 2) {
        bool ok;
        int firstByte = addr.left(2).toInt(&ok, 16);
        if (ok && (firstByte & 0x01))
            return QStringLiteral("Broadcast / Multicast");
    }

    /* Aggregate frame counts across all pairs involving this node */
    quint64 beacons  = 0;
    quint64 mgmt     = 0;
    quint64 data     = 0;

    for (const GraphEdge &e : m_edges) {
        if (!e.pair || !e.pair->is_wifi) continue;
        bool involves = (e.srcIdx == nodeIdx || e.dstIdx == nodeIdx);
        if (!involves) continue;

        /* Beacons are always sent by the AP (source node) */
        if (e.srcIdx == nodeIdx)
            beacons += e.pair->beacon_count;

        mgmt += e.pair->mgmt_frame_count;
        data += e.pair->data_frame_count;

        /* Also check reverse pair */
        if (e.reversePair) {
            if (e.dstIdx == nodeIdx)        /* reversed: this node is the src there */
                beacons += e.reversePair->beacon_count;
            mgmt += e.reversePair->mgmt_frame_count;
            data += e.reversePair->data_frame_count;
        }
    }

    if (beacons > 0)    return QStringLiteral("Access Points");
    if (mgmt >= data)   return QStringLiteral("Management");
    return                     QStringLiteral("Data Stations");
}

/* Fixed colours for WiFi cluster categories */
QColor GraphWidget::wifiClusterColor(const QString &key)
{
    if (key == QStringLiteral("Access Points"))        return QColor( 52, 152, 219);  /* blue   */
    if (key == QStringLiteral("Management"))           return QColor(230, 126,  34);  /* orange */
    if (key == QStringLiteral("Data Stations"))        return QColor( 39, 174,  96);  /* green  */
    if (key == QStringLiteral("Broadcast / Multicast"))return QColor(200, 160,  64);  /* amber  */
    return QColor(120, 120, 120);                                                      /* grey   */
}

/* Fixed cluster colour palette — assigned by hashing the subnet key. */
static QColor clusterPaletteColor(const QString &key)
{
    static const QColor palette[] = {
        QColor( 70, 130, 180),  /* steel blue   — internal */
        QColor( 39, 174,  96),  /* green        — internal */
        QColor( 26, 188, 156),  /* teal         — internal */
        QColor(155,  89, 182),  /* violet       — internal */
        QColor( 52, 152, 219),  /* light blue   — internal */
        QColor(230, 126,  34),  /* orange       — external */
        QColor(231,  76,  60),  /* red          — external */
        QColor(200, 160,  64),  /* amber        — multicast */
        QColor(160, 100, 200),  /* purple       — MAC */
        QColor(120, 120, 120),  /* grey         — other */
    };
    /* Deterministic but stable colouring for well-known keys */
    if (key == QStringLiteral("External"))              return palette[5];
    if (key == QStringLiteral("MAC"))                   return palette[8];
    if (key == QStringLiteral("IPv6"))                  return palette[3];
    if (key == QStringLiteral("Multicast"))             return palette[7];
    if (key == QStringLiteral("127.x (Loopback)"))      return palette[9];
    if (key == QStringLiteral("169.254.x (Link-Local)"))return palette[9];

    /* Internal subnets — rotate through cool colours */
    uint h = qHash(key, 0x9e3779b9u);
    return palette[h % 5];  /* indices 0-4 are the cool internal colours */
}

/* ─────────────────────────────────────────────────────────────────────── *
 *  Construction / destruction
 * ─────────────────────────────────────────────────────────────────────── */

GraphWidget::GraphWidget(QWidget *parent)
    : QWidget(parent)
    , m_pairs(nullptr)
    , m_protocols(nullptr)
    , m_edgeColorMode(COLOR_PROTOCOL)
    , m_nodeColorMode(NODECOLOR_SERVICE)
    , m_layoutMode(LAYOUT_STAR)
    , m_useBytes(FALSE)
    , m_showThickness(FALSE)
    , m_darkTheme(true)
    , m_wifiMode(false)
    , m_positionsLocked(false)
    , m_maxPairs(10)
    , m_thresholds(GraphThresholds::defaults())
    , m_legendHasUnknown(false)
    , m_legendFilterIsNode(false)
    , m_legendFilterPort(0)
    , m_hoveredNode(-1)
    , m_hoveredEdge(-1)
    , m_draggedNode(-1)
    , m_dragging(false)
    , m_dragMoved(false)
    , m_draggedCluster(-1)
    , m_internalSubnets(defaultInternalSubnets())
    , m_scale(1.0)
    , m_panOffset(0.0, 0.0)
    , m_panning(false)
    , m_spaceHeld(false)
    , m_blinkTimer(nullptr)
    , m_blinkState(false)
{
    setMinimumSize(300, 300);
    setMouseTracking(true);
    setFocusPolicy(Qt::ClickFocus);  /* receive key events after user clicks widget */

    m_blinkTimer = new QTimer(this);
    m_blinkTimer->setInterval(500);
    connect(m_blinkTimer, &QTimer::timeout, this, [this]() {
        m_blinkState = !m_blinkState;
        if (!m_selectedPairs.isEmpty() || !m_highlightedLabels.isEmpty()) update();
    });
}

GraphWidget::~GraphWidget() {}

/* ─────────────────────────────────────────────────────────────────────── *
 *  Public interface (CircleWidget-compatible)
 * ─────────────────────────────────────────────────────────────────────── */

void GraphWidget::setPairs(GList *pairs, GHashTable *protocols)
{
    m_pairs     = pairs;
    m_protocols = protocols;
    m_hoveredNode = -1;
    m_hoveredEdge = -1;
    m_draggedNode = -1;
    m_dragging    = false;
    m_legendFilterColor = QColor();  /* reset any active legend filter */
    m_legendFilterPort  = 0;

    buildGraph();
    update();
}

void GraphWidget::setMaxPairs(guint max_pairs)   { m_maxPairs = max_pairs; update(); }
void GraphWidget::setUseBytes(gboolean v)        { m_useBytes = v; computeEdgeVisuals(); update(); }
void GraphWidget::setShowLineThickness(gboolean v){ m_showThickness = v; computeEdgeVisuals(); update(); }
void GraphWidget::setProtocolFilter(QSet<QString> p){ m_enabledProtocols = p; update(); }
void GraphWidget::setHighlightedLabels(const QSet<QString> &l){ m_highlightedLabels = l; update(); }
void GraphWidget::setWiFiMode(bool wifi)
{
    m_wifiMode = wifi;
    if (!m_nodes.isEmpty()) { computeEdgeVisuals(); update(); }
}

void GraphWidget::setVisiblePairs(QSet<comm_pair_t*> visible)
{
    m_visiblePairs = visible;
    update();
}

void GraphWidget::setSelectedPairs(QList<comm_pair_t*> selected)
{
    m_selectedPairs = selected;
    if (selected.isEmpty()) m_blinkTimer->stop();
    else                    m_blinkTimer->start();
    update();
}

void GraphWidget::setDarkTheme(bool dark)
{
    m_darkTheme = dark;
    computeNodeColors();
    computeEdgeVisuals();
    update();
}

/* ── Graph-specific ─────────────────────────────────────────────────── */

void GraphWidget::setEdgeColorMode(EdgeColorMode mode)
{
    m_edgeColorMode = mode;
    m_legendFilterColor = QColor();  /* reset filter — legend items change */
    m_legendFilterPort  = 0;
    computeEdgeVisuals();
    update();
}

void GraphWidget::setNodeColorMode(NodeColorMode mode)
{
    m_nodeColorMode = mode;
    m_legendFilterColor = QColor();  /* reset filter — legend items change */
    m_legendFilterPort  = 0;
    computeNodeColors();
    if (m_layoutMode == LAYOUT_CLUSTER)
        applyLayout();  /* cluster grouping depends on node colour mode */
    update();
}

void GraphWidget::setLayoutMode(LayoutMode mode)
{
    m_layoutMode = mode;
    applyLayout();
    update();
}

void GraphWidget::relayout()
{
    /* Reset positions and zoom so applyLayout re-initialises from scratch */
    for (GraphNode &n : m_nodes) n.pos = QPointF(0, 0);
    m_scale     = 1.0;
    m_panOffset = QPointF(0.0, 0.0);
    applyLayout();
    update();
}

void GraphWidget::lockPositions(bool locked) { m_positionsLocked = locked; }

/* ── Zoom / pan helpers ─────────────────────────────────────────────── */

QPointF GraphWidget::screenToWorld(const QPointF &screenPos) const
{
    return (screenPos - m_panOffset) / m_scale;
}

static void applyZoomAtPoint(qreal &scale, QPointF &panOffset,
                              qreal newScale, const QPointF &screenAnchor)
{
    /* Keep the world point under screenAnchor fixed on screen */
    QPointF worldAnchor = (screenAnchor - panOffset) / scale;
    scale     = newScale;
    panOffset = screenAnchor - worldAnchor * scale;
}

void GraphWidget::zoomIn()
{
    qreal ns = qMin(m_scale * 1.25, 10.0);
    applyZoomAtPoint(m_scale, m_panOffset, ns,
                     QPointF(width() / 2.0, height() / 2.0));
    update();
}

void GraphWidget::zoomOut()
{
    qreal ns = qMax(m_scale / 1.25, 0.1);
    applyZoomAtPoint(m_scale, m_panOffset, ns,
                     QPointF(width() / 2.0, height() / 2.0));
    update();
}

void GraphWidget::zoomReset()
{
    m_scale     = 1.0;
    m_panOffset = QPointF(0.0, 0.0);
    update();
}

/* ─────────────────────────────────────────────────────────────────────── *
 *  Graph construction
 * ─────────────────────────────────────────────────────────────────────── */

void GraphWidget::buildGraph()
{
    m_nodes.clear();
    m_edges.clear();
    m_addrToNode.clear();
    m_clusters.clear();
    m_superClusters.clear();
    m_legendServices.clear();
    m_legendHasUnknown = false;
    m_scale     = 1.0;
    m_panOffset = QPointF(0.0, 0.0);

    if (!m_pairs) return;

    /* ── Collect per-node totals ───────────────────────────────────── */
    QHash<QString, quint64> addrBytes, addrPackets;
    QHash<QString, QString> addrDisplay;
    /* Per-node port aggregate: addr → { port → packet_count }
     * addrPorts  — both directions (used for topPort / SERVICE colour)
     * addrDstPorts — destination only (used for service category: identifies servers) */
    QHash<QString, QHash<quint16, quint64>> addrPorts;
    QHash<QString, QHash<quint16, quint64>> addrDstPorts;

    for (GList *it = m_pairs; it; it = it->next) {
        auto *pair = static_cast<comm_pair_t*>(it->data);
        if (!pair || !pair->src_addr || !pair->dst_addr) continue;

        QString src = QString::fromUtf8(pair->src_addr);
        QString dst = QString::fromUtf8(pair->dst_addr);
        addrBytes[src]   += pair->byte_count;
        addrBytes[dst]   += pair->byte_count;
        addrPackets[src] += pair->packet_count;
        addrPackets[dst] += pair->packet_count;
        if (!addrDisplay.contains(src))
            addrDisplay[src] = pair->resolved_src ? QString::fromUtf8(pair->resolved_src) : src;
        if (!addrDisplay.contains(dst))
            addrDisplay[dst] = pair->resolved_dst ? QString::fromUtf8(pair->resolved_dst) : dst;

        /* Aggregate ports for both endpoints (SERVICE colour / topPort) */
        if (pair->dst_ports) {
            GHashTableIter iter;
            gpointer key, value;
            g_hash_table_iter_init(&iter, pair->dst_ports);
            while (g_hash_table_iter_next(&iter, &key, &value)) {
                auto *ps = static_cast<port_stats_t*>(value);
                if (!ps) continue;
                quint16 p = (quint16)(uintptr_t)key;
                addrPorts[dst][p] += ps->count;
                addrPorts[src][p] += ps->count;
                /* Server-side only: dst receives connections on these ports */
                addrDstPorts[dst][p] += ps->count;
            }
        }
    }

    /* ── Create nodes ─────────────────────────────────────────────── */
    quint64 maxBytes = 1;
    for (auto it = addrBytes.constBegin(); it != addrBytes.constEnd(); ++it)
        maxBytes = qMax(maxBytes, it.value());

    /* Node radius: matches CircleWidget formula (dim/75) — same visual size as circle view */
    qreal baseR = qMax(8.0, qMin((qreal)width(), (qreal)height()) / 75.0);

    for (auto it = addrBytes.constBegin(); it != addrBytes.constEnd(); ++it) {
        const QString &addr = it.key();
        quint64 bytes = it.value();
        Q_UNUSED(bytes)  /* No longer used for scaling; kept for totalBytes field */

        /* Find top port for this node */
        quint16 topPort = 0;
        quint64 topCnt  = 0;
        const auto &ports = addrPorts[addr];
        for (auto pit = ports.constBegin(); pit != ports.constEnd(); ++pit) {
            if (pit.value() > topCnt) { topCnt = pit.value(); topPort = pit.key(); }
        }

        GraphNode node;
        node.rawAddr         = addr;
        node.displayLabel    = addrDisplay.value(addr, addr);
        node.pos             = QPointF(0, 0);
        node.hexRadius       = baseR;
        node.totalBytes      = bytes;
        node.totalPackets    = addrPackets.value(addr, 0);
        node.topPort         = topPort;
        node.serviceCategory = classifyServiceCategory(addrDstPorts.value(addr));
        node.color           = QColor(120, 120, 120); /* placeholder; set by computeNodeColors */

        m_addrToNode[addr] = (int)m_nodes.size();
        m_nodes.append(node);
    }

    /* ── Create edges ─────────────────────────────────────────────── */
    QHash<QString, comm_pair_t*> pairLookup;
    for (GList *it = m_pairs; it; it = it->next) {
        auto *pair = static_cast<comm_pair_t*>(it->data);
        if (!pair || !pair->src_addr || !pair->dst_addr) continue;
        pairLookup[QString::fromUtf8(pair->src_addr) + "|" + QString::fromUtf8(pair->dst_addr)] = pair;
    }

    QSet<QString> added;
    for (GList *it = m_pairs; it; it = it->next) {
        auto *pair = static_cast<comm_pair_t*>(it->data);
        if (!pair || !pair->src_addr || !pair->dst_addr) continue;

        QString src = QString::fromUtf8(pair->src_addr);
        QString dst = QString::fromUtf8(pair->dst_addr);
        QString a = (src <= dst) ? src : dst;
        QString b = (src <= dst) ? dst : src;
        QString key = a + "|" + b;
        if (added.contains(key)) continue;
        added.insert(key);

        comm_pair_t *revP = pairLookup.value(
            QString::fromUtf8(pair->dst_addr) + "|" + QString::fromUtf8(pair->src_addr), nullptr);

        GraphEdge edge;
        edge.pair          = pair;
        edge.reversePair   = revP;
        edge.srcIdx        = m_addrToNode.value(src, -1);
        edge.dstIdx        = m_addrToNode.value(dst, -1);
        edge.bidirectional = (revP != nullptr);
        edge.thickness     = 1.5;
        edge.color         = protocolColor(pair->top_protocol);
        edge.opacity       = 0.8;
        edge.healthScore   = 0.5;
        edge.anomalyScore  = 0.0;
        edge.responseTimeMs = -1.0;
        edge.throughputBps  = 0.0;
        if (edge.srcIdx >= 0 && edge.dstIdx >= 0 && edge.srcIdx != edge.dstIdx)
            m_edges.append(edge);
    }

    /* ── Build service legend: all known-service ports seen in any pair ── */
    {
        QHash<quint16, quint64> portPkts;
        for (GList *it = m_pairs; it; it = it->next) {
            auto *pair = static_cast<comm_pair_t*>(it->data);
            if (!pair || !pair->dst_ports) continue;
            GHashTableIter iter;
            gpointer pkey, pval;
            g_hash_table_iter_init(&iter, pair->dst_ports);
            while (g_hash_table_iter_next(&iter, &pkey, &pval)) {
                auto *ps = static_cast<port_stats_t*>(pval);
                if (!ps) continue;
                quint16 port = (quint16)(uintptr_t)pkey;
                portPkts[port] += ps->count;
            }
        }
        for (auto it = portPkts.constBegin(); it != portPkts.constEnd(); ++it) {
            quint16 port   = it.key();
            QString name   = graphPortServiceName(port);
            if (!name.isEmpty()) {
                ServiceEntry se;
                se.port    = port;
                se.name    = name;
                se.color   = portServiceColor(port);
                se.packets = it.value();
                m_legendServices.append(se);
            } else {
                m_legendHasUnknown = true;
            }
        }
        std::sort(m_legendServices.begin(), m_legendServices.end(),
            [](const ServiceEntry &a, const ServiceEntry &b) {
                return a.packets > b.packets;
            });
    }

    computeNodeColors();
    computeEdgeVisuals();
    applyLayout();
}

/* ─────────────────────────────────────────────────────────────────────── *
 *  Node colours
 * ─────────────────────────────────────────────────────────────────────── */

/* RSSI signal-quality colour — mirrors CircleWidget::getRssiColor()
 * Forward-declared here so it can be used by both computeNodeColors()
 * and computeEdgeVisuals().
 *   Excellent: >= -55 dBm  → green
 *   Good:     -65..-56     → yellow-green
 *   Fair:     -75..-66     → orange
 *   Poor:     < -75        → red
 *   No data               → grey */
static QColor rssiColor(const comm_pair_t *pair)
{
    if (!pair || !pair->is_wifi || pair->rssi_count == 0)
        return QColor(160, 160, 160);
    int avg = (int)((qreal)pair->rssi_sum / (qreal)pair->rssi_count);
    if (avg >= -55) return QColor(  0, 200,   0);   /* green        — excellent */
    if (avg >= -65) return QColor(160, 220,   0);   /* yellow-green — good      */
    if (avg >= -75) return QColor(255, 165,   0);   /* orange       — fair      */
    return           QColor(220,  30,  30);          /* red          — poor      */
}

void GraphWidget::computeNodeColors()
{
    /* In WiFi mode: color nodes by average RSSI across all their edges */
    if (m_wifiMode) {
        for (int ni = 0; ni < (int)m_nodes.size(); ni++) {
            gint32 rssiSum   = 0;
            guint32 rssiCount = 0;
            for (const GraphEdge &e : m_edges) {
                if ((e.srcIdx == ni || e.dstIdx == ni) && e.pair && e.pair->is_wifi) {
                    rssiSum   += e.pair->rssi_sum;
                    rssiCount += e.pair->rssi_count;
                }
            }
            /* Build a synthetic comm_pair_t stub just for the color helper */
            comm_pair_t stub;
            memset(&stub, 0, sizeof(stub));
            stub.is_wifi    = TRUE;
            stub.rssi_sum   = rssiSum;
            stub.rssi_count = rssiCount;
            m_nodes[ni].color = rssiColor(&stub);
        }
        return;
    }

    for (GraphNode &node : m_nodes) {
        switch (m_nodeColorMode) {
            case NODECOLOR_SERVICE:
                node.color = serviceColor(node.topPort);
                break;
            case NODECOLOR_ROLE:
                node.color = roleColor(node);
                break;
            case NODECOLOR_PROTOCOL: {
                /* Find dominant protocol across all edges for this node */
                QHash<QString, quint64> protoCounts;
                for (const GraphEdge &e : m_edges) {
                    if (e.srcIdx < 0 || e.dstIdx < 0) continue;
                    bool involves = (m_nodes[e.srcIdx].rawAddr == node.rawAddr ||
                                     m_nodes[e.dstIdx].rawAddr == node.rawAddr);
                    if (involves && e.pair && e.pair->top_protocol)
                        protoCounts[QString::fromUtf8(e.pair->top_protocol)] +=
                            m_useBytes ? e.pair->byte_count : e.pair->packet_count;
                }
                QString best;
                quint64 bestV = 0;
                for (auto it = protoCounts.constBegin(); it != protoCounts.constEnd(); ++it)
                    if (it.value() > bestV) { bestV = it.value(); best = it.key(); }
                node.color = best.isEmpty()
                    ? QColor(120, 120, 120)
                    : protocolColor(best.toUtf8().constData());
                break;
            }
            case NODECOLOR_FUNCTION:
                node.color = node.serviceCategory != SC_NONE
                    ? serviceCategoryColor(node.serviceCategory)
                    : (m_darkTheme ? QColor(100, 100, 100) : QColor(150, 150, 150)); /* uncategorised — grey */
                break;
        }
    }
}

/* ─────────────────────────────────────────────────────────────────────── *
 *  Phase 2 scoring — TCP Health and Anomaly
 *
 *  Both scores are derived solely from per-pair aggregate data available in
 *  comm_pair_t: byte/packet counts, dst_ports table, top_protocol string,
 *  and whether a reverse pair (bidirectional traffic) exists.
 * ─────────────────────────────────────────────────────────────────────── */

/* TCP Health score — 0.0 (unhealthy) … 1.0 (healthy).
 * Signals evaluated:
 *   + avg packet size > 300 B: data flowing → good
 *   + recognised app protocol: handshake completed → good
 *   + high packet count: sustained connection → good
 *   − avg packet size < 100 B: likely SYN/RST-only → poor
 *   − raw "TCP" with no app protocol: unknown state → poor
 *   − many unique destination ports on one pair: unusual for TCP → poor
 *   − fewer than 4 packets: too brief to judge → slight penalty */
static qreal tcpHealthScore(const comm_pair_t *pair,
                             const GraphWidget::GraphThresholds &T,
                             QList<GraphWidget::ScoreFactor> *factors = nullptr)
{
    if (!pair || !pair->has_tcp) return 0.5;  /* neutral for non-TCP */

    auto addF = [factors](const QString &desc, qreal d) {
        if (factors) factors->append({desc, d});
    };

    qreal score = 0.5;
    qreal avgPkt = (pair->packet_count > 0)
        ? (qreal)pair->byte_count / (qreal)pair->packet_count : 0.0;

    /* Packet size signals */
    if      (avgPkt > T.hs_pkt_large)    { score += 0.25; addF(QString("Avg packet size %1 B — large payload").arg((int)avgPkt), +0.25); }
    else if (avgPkt > T.hs_pkt_moderate) { score += 0.15; addF(QString("Avg packet size %1 B — moderate payload").arg((int)avgPkt), +0.15); }
    else if (avgPkt > T.hs_pkt_small)    { score += 0.05; addF(QString("Avg packet size %1 B — small payload").arg((int)avgPkt), +0.05); }
    else if (avgPkt < T.hs_pkt_tiny)     { score -= 0.30; addF(QString("Avg packet size %1 B — SYN/RST control traffic").arg((int)avgPkt), -0.30); }

    /* Application-layer identity */
    bool isRawTcp = (g_strcmp0(pair->top_protocol, "TCP") == 0);
    if (isRawTcp) {
        score -= 0.15;
        addF("No identified application protocol (raw TCP)", -0.15);
    } else {
        score += 0.15;
        addF(QString("Identified protocol: %1").arg(QLatin1String(pair->top_protocol)), +0.15);
    }

    /* Packet volume */
    if      ((int)pair->packet_count < T.hs_pkt_very_few)  { score -= 0.20; addF(QString("%1 packets — refused / half-open").arg(pair->packet_count), -0.20); }
    else if ((int)pair->packet_count < T.hs_pkt_few)        { score -= 0.10; addF(QString("%1 packets — brief connection").arg(pair->packet_count), -0.10); }
    else if ((int)pair->packet_count > T.hs_pkt_sustained)  { score += 0.10; addF(QString("%1 packets — sustained connection").arg(pair->packet_count), +0.10); }

    /* Port diversity — unusual for a single TCP session */
    int nPorts = pair->dst_ports ? (int)g_hash_table_size(pair->dst_ports) : 0;
    if      (nPorts > T.hs_ports_high)     { score -= 0.25; addF(QString("%1 destination ports — unusual for TCP").arg(nPorts), -0.25); }
    else if (nPorts > T.hs_ports_elevated) { score -= 0.10; addF(QString("%1 destination ports — slightly unusual").arg(nPorts), -0.10); }

    return qBound(0.0, score, 1.0);
}

/* Anomaly score — 0.0 (clean) … 1.0 (highly anomalous).
 * Signals evaluated:
 *   + many unique destination ports (port scan behaviour)
 *   + few packets per unique port (high-speed scan)
 *   + very small avg packet size at high volume (SYN-flood pattern)
 *   + raw TCP with many ports (no application = scan-like)
 *   + dangerous legacy protocols in destination ports (Telnet, rsh, TFTP)
 *   + one-way high-volume traffic (potential exfiltration) */
static qreal anomalyScore(const comm_pair_t *pair, bool hasReverse,
                           const GraphWidget::GraphThresholds &T,
                           QList<GraphWidget::ScoreFactor> *factors = nullptr)
{
    if (!pair) return 0.0;

    auto addF = [factors](const QString &desc, qreal d) {
        if (factors) factors->append({desc, d});
    };

    qreal score = 0.0;
    int nPorts = pair->dst_ports ? (int)g_hash_table_size(pair->dst_ports) : 0;

    /* Port diversity */
    if      (nPorts > T.an_ports_critical)  { score += 0.50; addF(QString("%1 unique destination ports — port scan pattern").arg(nPorts), +0.50); }
    else if (nPorts > T.an_ports_high)      { score += 0.35; addF(QString("%1 unique destination ports — high diversity").arg(nPorts), +0.35); }
    else if (nPorts > T.an_ports_elevated)  { score += 0.20; addF(QString("%1 unique destination ports — elevated diversity").arg(nPorts), +0.20); }
    else if (nPorts > T.an_ports_slight)    { score += 0.08; addF(QString("%1 unique destination ports — slightly elevated").arg(nPorts), +0.08); }

    /* Packets per port — very low = rapid scan */
    if (nPorts > T.an_scan_min_ports && pair->packet_count > 0) {
        qreal ppp = (qreal)pair->packet_count / nPorts;
        if (ppp < T.an_scan_ppp) { score += 0.20; addF(QString("%.1f packets/port — rapid scan rate").arg(ppp), +0.20); }
    }

    /* Tiny-packet + high-volume pattern */
    qreal avgPkt = (pair->packet_count > 0)
        ? (qreal)pair->byte_count / (qreal)pair->packet_count : 0.0;
    if      (avgPkt < T.an_flood_tiny_pkt  && (int)pair->packet_count > T.an_flood_tiny_count)
        { score += 0.25; addF(QString("Avg %1 B/pkt x %2 pkts — SYN flood pattern").arg((int)avgPkt).arg(pair->packet_count), +0.25); }
    else if (avgPkt < T.an_flood_small_pkt && (int)pair->packet_count > T.an_flood_small_count)
        { score += 0.10; addF(QString("Avg %1 B/pkt x %2 pkts — small-packet flood").arg((int)avgPkt).arg(pair->packet_count), +0.10); }

    /* Raw TCP with multiple ports and no application protocol */
    bool isRawTcp = (g_strcmp0(pair->top_protocol, "TCP") == 0);
    if (isRawTcp && nPorts > 1)                        { score += 0.15; addF("Raw TCP (no app protocol) across multiple ports", +0.15); }
    if (isRawTcp && avgPkt < T.an_flood_small_pkt)     { score += 0.10; addF("Raw TCP with tiny packets — unknown / control only", +0.10); }

    /* Legacy / dangerous destination ports */
    if (pair->dst_ports) {
        if (g_hash_table_contains(pair->dst_ports, GUINT_TO_POINTER(23u)))  { score += 0.20; addF("Port 23 (Telnet) — plaintext remote shell", +0.20); }
        if (g_hash_table_contains(pair->dst_ports, GUINT_TO_POINTER(513u))) { score += 0.15; addF("Port 513 (rlogin) — legacy insecure login", +0.15); }
        if (g_hash_table_contains(pair->dst_ports, GUINT_TO_POINTER(514u))) { score += 0.15; addF("Port 514 (rsh) — legacy insecure shell", +0.15); }
        if (g_hash_table_contains(pair->dst_ports, GUINT_TO_POINTER(69u)))  { score += 0.10; addF("Port 69 (TFTP) — unauthenticated file transfer", +0.10); }
    }

    /* One-way high-volume (asymmetric transfer) */
    if (!hasReverse && (int)pair->packet_count > T.an_oneway_count)
        { score += 0.15; addF(QString("One-way %1 packets — no reverse flow (possible exfiltration)").arg(pair->packet_count), +0.15); }

    return qBound(0.0, score, 1.0);
}

/* Map a continuous health score to a traffic-light colour */
static QColor healthColor(qreal hs)
{
    if      (hs >= 0.75) return QColor( 39, 174,  96);  /* green   — healthy   */
    else if (hs >= 0.50) return QColor(241, 196,  15);  /* yellow  — moderate  */
    else if (hs >= 0.28) return QColor(230, 126,  34);  /* orange  — degraded  */
    else                 return QColor(231,  76,  60);  /* red     — unhealthy */
}

/* Map a continuous anomaly score to a traffic-light colour */
static QColor anomalyColor(qreal as)
{
    if      (as <= 0.12) return QColor( 39, 174,  96);  /* green   — clean      */
    else if (as <= 0.30) return QColor(241, 196,  15);  /* yellow  — noteworthy */
    else if (as <= 0.55) return QColor(230, 126,  34);  /* orange  — suspicious */
    else                 return QColor(231,  76,  60);  /* red     — anomalous  */
}

/* Response-time colour — 5 bins driven by active threshold profile */
static QColor responseTimeColor(qreal ms, const GraphWidget::GraphThresholds &T)
{
    if      (ms < 0)                  return QColor(160, 160, 160);  /* grey   — unavailable  */
    else if (ms < T.rt_fast_ms)       return QColor( 39, 174,  96);  /* green  — fast         */
    else if (ms < T.rt_moderate_ms)   return QColor(130, 200,  60);  /* yellow-green          */
    else if (ms < T.rt_slow_ms)       return QColor(241, 196,  15);  /* yellow — slow         */
    else if (ms < T.rt_very_slow_ms)  return QColor(230, 126,  34);  /* orange — very slow    */
    else                              return QColor(231,  76,  60);  /* red    — unacceptable */
}

/* Throughput colour — 5 bins (bytes/sec) */
static QColor throughputColor(qreal bps)
{
    if      (bps <=         0) return QColor(160, 160, 160);  /* grey         — unknown      */
    else if (bps <     10000)  return QColor(231,  76,  60);  /* red          — < 10 KB/s   */
    else if (bps <    100000)  return QColor(230, 126,  34);  /* orange       — 10–100 KB/s */
    else if (bps <   1000000)  return QColor(241, 196,  15);  /* yellow       — 100KB–1MB/s */
    else if (bps <  10000000)  return QColor(130, 200,  60);  /* yellow-green — 1–10 MB/s   */
    else                       return QColor( 39, 174,  96);  /* green        — > 10 MB/s   */
}

/* Window pressure colour — prioritises zero-window events, then minimum window size */
static QColor windowPressureColor(guint32 winMin, guint32 zeroWinCount)
{
    if (winMin == G_MAXUINT32)  return QColor(160, 160, 160);  /* grey         — no TCP window data  */
    if (zeroWinCount > 0)       return QColor(231,  76,  60);  /* red          — zero-window stall   */
    if (winMin <  4096)         return QColor(230, 126,  34);  /* orange       — severely constrained */
    if (winMin <  8192)         return QColor(241, 196,  15);  /* yellow       — constrained          */
    if (winMin < 32768)         return QColor(130, 200,  60);  /* yellow-green — mildly constrained   */
    return                             QColor( 39, 174,  96);  /* green        — healthy (>= 32 KB)   */
}

/* ─────────────────────────────────────────────────────────────────────── *
 *  Edge visuals
 * ─────────────────────────────────────────────────────────────────────── */

void GraphWidget::computeEdgeVisuals()
{
    if (m_edges.isEmpty()) return;
    quint64 maxVol = 1, maxPkts = 1;
    for (const GraphEdge &e : m_edges) {
        if (!e.pair) continue;
        quint64 vol  = m_useBytes ? e.pair->byte_count  : e.pair->packet_count;
        quint64 pkts = e.pair->packet_count;
        if (e.reversePair) { vol += m_useBytes ? e.reversePair->byte_count : e.reversePair->packet_count;
                             pkts += e.reversePair->packet_count; }
        maxVol  = qMax(maxVol,  vol);
        maxPkts = qMax(maxPkts, pkts);
    }
    for (GraphEdge &e : m_edges) {
        if (!e.pair) continue;
        quint64 vol  = m_useBytes ? e.pair->byte_count  : e.pair->packet_count;
        quint64 pkts = e.pair->packet_count;
        if (e.reversePair) { vol += m_useBytes ? e.reversePair->byte_count : e.reversePair->packet_count;
                             pkts += e.reversePair->packet_count; }
        qreal logVol  = qLn(1.0 + (qreal)vol)  / qLn(1.0 + (qreal)maxVol);
        qreal logPkts = qLn(1.0 + (qreal)pkts) / qLn(1.0 + (qreal)maxPkts);
        e.thickness = m_showThickness ? (1.0 + 6.0 * logVol) : 1.5;
        e.opacity   = 0.25 + 0.75 * logPkts;

        /* Always compute both scores so tooltips can show them in any mode */
        bool hasPeer = (e.reversePair != nullptr);
        qreal hs = tcpHealthScore(e.pair, m_thresholds);
        qreal as = anomalyScore(e.pair, hasPeer, m_thresholds);
        if (hasPeer) {
            hs = qMin(hs, tcpHealthScore(e.reversePair, m_thresholds));
            as = qMax(as, anomalyScore(e.reversePair, true, m_thresholds));
        }
        e.healthScore  = hs;
        e.anomalyScore = as;

        /* Response time: time from first forward packet to first reverse packet (ms).
         * Requires both directions to have timestamp data.                           */
        e.responseTimeMs = -1.0;  /* −1 = unavailable */
        if (e.pair && e.pair->first_ts > 0.0 &&
            e.reversePair && e.reversePair->first_ts > 0.0)
        {
            qreal diff = (e.reversePair->first_ts - e.pair->first_ts) * 1000.0;
            e.responseTimeMs = qMax(0.0, diff);  /* clamp: clock skew can give tiny negatives */
        }

        /* Throughput: bytes / connection duration (bytes per second).
         * Use combined bytes and the wider time window across both directions.       */
        e.throughputBps = 0.0;
        {
            gdouble t0 = e.pair->first_ts;
            gdouble t1 = e.pair->last_ts;
            quint64 totalBytes = e.pair->byte_count;
            if (e.reversePair && e.reversePair->first_ts > 0.0) {
                t0 = qMin(t0, (qreal)e.reversePair->first_ts);
                t1 = qMax(t1, (qreal)e.reversePair->last_ts);
                totalBytes += e.reversePair->byte_count;
            }
            qreal dur = t1 - t0;
            if (dur > 0.001)  /* at least 1 ms to avoid division by noise */
                e.throughputBps = (qreal)totalBytes / dur;
        }

        /* TCP window stats — merged across both directions */
        e.winMin          = G_MAXUINT32;
        e.winMax          = 0;
        e.winAvg          = 0.0;
        e.zeroWinCount    = 0;
        e.zeroWinMaxDurMs = 0.0;
        {
            guint32 totalWinSamples = 0;
            gdouble totalWinSum     = 0.0;
            auto mergeWin = [&](const comm_pair_t *p) {
                if (!p || !p->has_tcp || p->tcp_win_count == 0) return;
                if (p->tcp_win_min < e.winMin) e.winMin = p->tcp_win_min;
                if (p->tcp_win_max > e.winMax) e.winMax = p->tcp_win_max;
                totalWinSum     += p->tcp_win_sum;
                totalWinSamples += p->tcp_win_count;
                e.zeroWinCount  += p->tcp_zero_win_count;
                if (p->tcp_zero_win_max_dur_ms > e.zeroWinMaxDurMs)
                    e.zeroWinMaxDurMs = p->tcp_zero_win_max_dur_ms;
            };
            mergeWin(e.pair);
            mergeWin(e.reversePair);
            if (totalWinSamples > 0)
                e.winAvg = totalWinSum / (gdouble)totalWinSamples;
        }

        /* Edge color — in WiFi mode always use RSSI signal quality */
        if (m_wifiMode) {
            e.color = rssiColor(e.pair);
        } else {
            switch (m_edgeColorMode) {
                case COLOR_PROTOCOL:      e.color = protocolColor(e.pair->top_protocol); break;
                case COLOR_TCP_HEALTH:    e.color = healthColor(hs);  break;
                case COLOR_ANOMALY:       e.color = anomalyColor(as); break;
                case COLOR_RESPONSE_TIME: e.color = responseTimeColor(e.responseTimeMs, m_thresholds); break;
                case COLOR_THROUGHPUT:    e.color = throughputColor(e.throughputBps);    break;
                case COLOR_HIGH_RISK:     e.color = highRiskColor(e.pair);               break;
                case COLOR_TCP_WINDOW:    e.color = windowPressureColor(e.winMin, e.zeroWinCount); break;
            }
        }
    }
}

/* ─────────────────────────────────────────────────────────────────────── *
 *  Score breakdown (public API — used by ConnectionPopup Score button)
 * ─────────────────────────────────────────────────────────────────────── */

void GraphWidget::getScoreBreakdown(comm_pair_t *pair, comm_pair_t *reversePair,
                                     QList<ScoreFactor> *healthFactors,
                                     QList<ScoreFactor> *anomalyFactors,
                                     qreal *healthScoreOut,
                                     qreal *anomalyScoreOut,
                                     qreal *responseTimeMsOut,
                                     qreal *throughputBpsOut) const
{
    if (!pair) return;
    bool hasPeer = (reversePair != nullptr);

    /* Compute forward direction scores — fill factors from the forward pair */
    qreal hs_fwd = tcpHealthScore(pair, m_thresholds, healthFactors);
    qreal as_fwd = anomalyScore(pair, hasPeer, m_thresholds, anomalyFactors);

    qreal hs = hs_fwd;
    qreal as = as_fwd;

    if (hasPeer) {
        /* Combined: use the worse (lower health / higher anomaly) direction.
         * If the reverse direction is worse, replace the factors with its
         * breakdown and add a note at the top.                              */
        qreal hs_rev = tcpHealthScore(reversePair, m_thresholds, nullptr);
        qreal as_rev = anomalyScore(reversePair, true, m_thresholds, nullptr);

        if (hs_rev < hs_fwd) {
            hs = hs_rev;
            if (healthFactors) {
                healthFactors->clear();
                healthFactors->append({"Reverse direction scored lower (shown below):", 0.0});
                tcpHealthScore(reversePair, m_thresholds, healthFactors);
            }
        }
        if (as_rev > as_fwd) {
            as = as_rev;
            if (anomalyFactors) {
                anomalyFactors->clear();
                anomalyFactors->append({"Reverse direction scored higher (shown below):", 0.0});
                anomalyScore(reversePair, true, m_thresholds, anomalyFactors);
            }
        }
    }

    if (healthScoreOut)  *healthScoreOut  = hs;
    if (anomalyScoreOut) *anomalyScoreOut = as;

    /* Response time: first-packet round-trip delay (same formula as setPairs) */
    if (responseTimeMsOut) {
        *responseTimeMsOut = -1.0;
        if (pair->first_ts > 0.0 && reversePair && reversePair->first_ts > 0.0) {
            qreal diff = (reversePair->first_ts - pair->first_ts) * 1000.0;
            *responseTimeMsOut = qMax(0.0, diff);
        }
    }

    /* Throughput: combined bytes / connection duration (same formula as setPairs) */
    if (throughputBpsOut) {
        *throughputBpsOut = 0.0;
        gdouble t0 = pair->first_ts;
        gdouble t1 = pair->last_ts;
        quint64 totalBytes = pair->byte_count;
        if (reversePair) {
            t0 = qMin(t0, reversePair->first_ts);
            t1 = qMax(t1, reversePair->last_ts);
            totalBytes += reversePair->byte_count;
        }
        qreal dur = t1 - t0;
        if (dur > 0.001)
            *throughputBpsOut = (qreal)totalBytes / dur;
    }
}

void GraphWidget::getEdgeWindowStats(comm_pair_t *pair,
                                      guint32 *winMinOut,
                                      guint32 *winMaxOut,
                                      gdouble *winAvgOut,
                                      guint32 *zeroWinCountOut,
                                      gdouble *zeroWinMaxDurMsOut) const
{
    for (const GraphEdge &e : m_edges) {
        if (e.pair != pair && e.reversePair != pair) continue;
        if (winMinOut)          *winMinOut          = e.winMin;
        if (winMaxOut)          *winMaxOut          = e.winMax;
        if (winAvgOut)          *winAvgOut          = e.winAvg;
        if (zeroWinCountOut)    *zeroWinCountOut    = e.zeroWinCount;
        if (zeroWinMaxDurMsOut) *zeroWinMaxDurMsOut = e.zeroWinMaxDurMs;
        return;
    }
}

/* ─────────────────────────────────────────────────────────────────────── *
 *  Layout algorithms
 * ─────────────────────────────────────────────────────────────────────── */

void GraphWidget::applyLayout()
{
    if (m_nodes.isEmpty()) return;

    /* Clear clusters — repopulated only by layoutCluster() */
    m_clusters.clear();
    m_superClusters.clear();

    switch (m_layoutMode) {
        case LAYOUT_FORCE:        layoutForce(150);    break;
        case LAYOUT_STAR:         layoutStar();        break;
        case LAYOUT_CIRCULAR:     layoutCircular();    break;
        case LAYOUT_GRID:         layoutGrid();        break;
        case LAYOUT_CLUSTER:      layoutCluster();     break;
        case LAYOUT_CONCENTRIC:   layoutConcentric();  break;
        case LAYOUT_HIERARCHICAL: layoutHierarchical(); break;
        case LAYOUT_RADIAL:       layoutRadial();      break;
    }

    /* Keep nodes away from the legend area (all layout modes) */
    protectLegendArea();
}

/* Fruchterman-Reingold with centre gravity.
 * Nodes initialised at deterministic random positions inside the widget
 * (seeded by address hash) — never on the border ring. */
void GraphWidget::layoutForce(int iterations)
{
    int N = (int)m_nodes.size();
    if (N == 0) return;

    const qreal margin = 60.0;
    qreal W = qMax(200.0, (qreal)width()  - 2 * margin);
    qreal H = qMax(200.0, (qreal)height() - 2 * margin);

    /* Seed positions: deterministic hash of address, spread inside interior */
    for (GraphNode &n : m_nodes) {
        if (n.pos == QPointF(0, 0)) {
            uint h = (uint)qHash(n.rawAddr, 0x9e3779b9u);
            qreal fx = (qreal)(h & 0xFFFF) / 65535.0;
            qreal fy = (qreal)((h >> 16) & 0xFFFF) / 65535.0;
            /* Keep inside 20-80% of the area to start well away from edges */
            n.pos = QPointF(margin + W * (0.20 + 0.60 * fx),
                            margin + H * (0.20 + 0.60 * fy));
        }
    }

    qreal k    = qSqrt((W * H) / qMax(1, N)) * 1.2;
    qreal temp = W / 3.0;

    QVector<QPointF> disp(N);

    for (int iter = 0; iter < iterations; iter++) {
        qreal cooling = qPow(1.0 - (qreal)iter / iterations, 1.5);
        qreal maxDisp = temp * cooling;

        for (int i = 0; i < N; i++) disp[i] = QPointF(0, 0);

        /* Repulsion O(N²) */
        for (int i = 0; i < N; i++) {
            for (int j = i + 1; j < N; j++) {
                QPointF d = m_nodes[i].pos - m_nodes[j].pos;
                qreal dist = qSqrt(d.x()*d.x() + d.y()*d.y());
                if (dist < 1.0) { dist = 1.0; d = QPointF(1, 0); }
                qreal fr = (k * k) / dist;
                QPointF f = d / dist * fr;
                disp[i] += f;
                disp[j] -= f;
            }
        }

        /* Attraction along edges */
        for (const GraphEdge &e : m_edges) {
            int i = e.srcIdx, j = e.dstIdx;
            if (i < 0 || j < 0 || i >= N || j >= N) continue;
            QPointF d = m_nodes[i].pos - m_nodes[j].pos;
            qreal dist = qSqrt(d.x()*d.x() + d.y()*d.y());
            if (dist < 1.0) { dist = 1.0; d = QPointF(1, 0); }
            qreal fa = (dist * dist) / k;
            quint64 vol = e.pair ? e.pair->byte_count : 0;
            if (e.reversePair) vol += e.reversePair->byte_count;
            qreal wt = 1.0 + 0.3 * qLn(1.0 + (qreal)vol / 50000.0);
            QPointF f = d / dist * fa * wt;
            disp[i] -= f;
            disp[j] += f;
        }

        /* Weak centre gravity — pulls nodes away from border */
        QPointF centre(margin + W / 2.0, margin + H / 2.0);
        for (int i = 0; i < N; i++) {
            QPointF g = centre - m_nodes[i].pos;
            disp[i] += g * 0.02;
        }

        /* Apply with cooling clamp */
        for (int i = 0; i < N; i++) {
            QPointF &d = disp[i];
            qreal dmag = qSqrt(d.x()*d.x() + d.y()*d.y());
            if (dmag > maxDisp && dmag > 0) d = d / dmag * maxDisp;
            m_nodes[i].pos += d;
            m_nodes[i].pos.setX(qBound(margin, m_nodes[i].pos.x(), margin + W));
            m_nodes[i].pos.setY(qBound(margin, m_nodes[i].pos.y(), margin + H));
        }
    }
}

/* Star layout: highest-traffic node at centre, others on one or more rings. */
void GraphWidget::layoutStar()
{
    int N = (int)m_nodes.size();
    if (N == 0) return;
    const qreal margin = 60.0;
    qreal W = qMax(200.0, (qreal)width()  - 2 * margin);
    qreal H = qMax(200.0, (qreal)height() - 2 * margin);
    QPointF centre(margin + W / 2.0, margin + H / 2.0);

    /* Find hub = node with most edges (degree) */
    QHash<int, int> degree;
    for (const GraphEdge &e : m_edges) {
        degree[e.srcIdx]++;
        degree[e.dstIdx]++;
    }
    int hubIdx = 0;
    int maxDeg = -1;
    for (auto it = degree.constBegin(); it != degree.constEnd(); ++it) {
        if (it.value() > maxDeg) { maxDeg = it.value(); hubIdx = it.key(); }
    }

    m_nodes[hubIdx].pos = centre;

    /* Remaining nodes on concentric rings */
    QList<int> others;
    for (int i = 0; i < N; i++) if (i != hubIdx) others.append(i);

    int perRing = qMax(6, (int)qCeil(2.0 * M_PI * (qMin(W, H) * 0.35) / 60.0));
    qreal ringR = qMin(W, H) * 0.35;

    int placed = 0;
    int ring   = 1;
    while (placed < others.size()) {
        int cnt = qMin(perRing * ring, (int)others.size() - placed);
        qreal r = ringR * ring;
        for (int i = 0; i < cnt && placed < others.size(); i++, placed++) {
            qreal angle = 2.0 * M_PI * i / cnt - M_PI / 2.0;
            int nIdx = others[placed];
            m_nodes[nIdx].pos = QPointF(centre.x() + r * qCos(angle),
                                        centre.y() + r * qSin(angle));
        }
        ring++;
    }
}

/* Circular layout: equal angular spacing, largest node at top. */
void GraphWidget::layoutCircular()
{
    int N = (int)m_nodes.size();
    if (N == 0) return;
    const qreal margin = 60.0;
    qreal W = qMax(200.0, (qreal)width()  - 2 * margin);
    qreal H = qMax(200.0, (qreal)height() - 2 * margin);
    QPointF centre(margin + W / 2.0, margin + H / 2.0);
    qreal r = qMin(W, H) * 0.42;

    /* Sort by traffic descending so biggest nodes start at top */
    QList<int> order;
    for (int i = 0; i < N; i++) order.append(i);
    std::sort(order.begin(), order.end(), [this](int a, int b) {
        return m_nodes[a].totalBytes > m_nodes[b].totalBytes;
    });

    for (int i = 0; i < N; i++) {
        qreal angle = 2.0 * M_PI * i / N - M_PI / 2.0;
        m_nodes[order[i]].pos = QPointF(centre.x() + r * qCos(angle),
                                        centre.y() + r * qSin(angle));
    }
}

/* Grid layout: nodes in a roughly-square grid, sorted by traffic. */
void GraphWidget::layoutGrid()
{
    int N = (int)m_nodes.size();
    if (N == 0) return;
    const qreal margin = 60.0;
    qreal W = qMax(200.0, (qreal)width()  - 2 * margin);
    qreal H = qMax(200.0, (qreal)height() - 2 * margin);

    int cols = (int)qCeil(qSqrt((qreal)N * W / H));
    cols = qMax(1, cols);
    int rows = (int)qCeil((qreal)N / cols);

    qreal cellW = W / cols;
    qreal cellH = H / rows;

    QList<int> order;
    for (int i = 0; i < N; i++) order.append(i);
    std::sort(order.begin(), order.end(), [this](int a, int b) {
        return m_nodes[a].totalBytes > m_nodes[b].totalBytes;
    });

    for (int i = 0; i < N; i++) {
        int col = i % cols;
        int row = i / cols;
        m_nodes[order[i]].pos = QPointF(margin + cellW * (col + 0.5),
                                        margin + cellH * (row + 0.5));
    }
}

/* Cluster layout: groups nodes by a context-sensitive key.
 *
 * Grouping strategy depends on the active node colour mode:
 *   WiFi mode          — 802.11 frame type (AP / Management / Data / Broadcast)
 *   NODECOLOR_FUNCTION — service category (Remote / Interactive / Messaging / Filetransfer / Other)
 *   NODECOLOR_ROLE     — network role (Internal / External / Broadcast / MAC)
 *   everything else    — IP subnet prefix (original behaviour)
 *
 * Each group gets a labelled background blob; nodes are arranged in a
 * mini-circle inside their cluster area.  Cluster centres are spread on
 * a larger circle (or grid for many clusters) so groups don't overlap. */
void GraphWidget::layoutCluster()
{
    int N = (int)m_nodes.size();
    if (N == 0) return;

    const qreal margin = 60.0;
    qreal W = qMax(200.0, (qreal)width()  - 2 * margin);
    qreal H = qMax(200.0, (qreal)height() - 2 * margin);

    /* ── Pre-pass: build per-node dominant protocol for NODECOLOR_PROTOCOL ── */
    QHash<int, QString> nodeDomProtocol;
    if (!m_wifiMode && m_nodeColorMode == NODECOLOR_PROTOCOL) {
        QHash<int, QHash<QString, quint64>> nodeProtoPkts;
        for (const GraphEdge &e : m_edges) {
            if (e.pair && e.pair->top_protocol) {
                QString proto = QString::fromUtf8(e.pair->top_protocol);
                quint64 pkts  = e.pair->packet_count;
                nodeProtoPkts[e.srcIdx][proto] += pkts;
                nodeProtoPkts[e.dstIdx][proto] += pkts;
            }
        }
        for (auto it = nodeProtoPkts.begin(); it != nodeProtoPkts.end(); ++it) {
            QString dom;
            quint64 maxPkts = 0;
            for (auto jt = it->begin(); jt != it->end(); ++jt) {
                if (jt.value() > maxPkts) { maxPkts = jt.value(); dom = jt.key(); }
            }
            nodeDomProtocol[it.key()] = dom;
        }
    }

    /* ── Step 1: assign each node to a cluster ── */
    int internalSubnetCount = 0;  /* increments for each new RFC1918 subnet cluster */

    QHash<QString, int> keyToCluster;
    for (int i = 0; i < N; i++) {
        QString key;
        if (m_wifiMode) {
            key = wifiClusterKey(i);
        } else if (m_nodeColorMode == NODECOLOR_FUNCTION) {
            switch (m_nodes[i].serviceCategory) {
                case SC_REMOTE:       key = "Remote Access";    break;
                case SC_INTERACTIVE:  key = "Interactive Shell"; break;
                case SC_MESSAGING:    key = "Messaging";         break;
                case SC_FILETRANSFER: key = "File Transfer";     break;
                default:              key = "Other";             break;
            }
        } else if (m_nodeColorMode == NODECOLOR_ROLE) {
            const QString &addr = m_nodes[i].rawAddr;
            if (addr.startsWith("224.") || addr.startsWith("239.") ||
                addr.startsWith("ff0")  || addr.startsWith("ff02") ||
                addr == "255.255.255.255" || addr.endsWith(".255"))
                key = "Broadcast / Multicast";
            else if (addr.count(':') == 5 && addr.length() == 17)
                key = "MAC / Layer-2";
            else if (isRFC1918(addr) || addr.startsWith("fe80"))
                key = clusterKeyForAddr(addr);  /* subnet (e.g. "192.168.1.x") */
            else
                key = "External / Internet";
        } else if (m_nodeColorMode == NODECOLOR_SERVICE) {
            quint16 p = m_nodes[i].topPort;
            key = graphPortServiceName(p);
            if (key.isEmpty()) key = "Other";
        } else if (m_nodeColorMode == NODECOLOR_PROTOCOL) {
            key = nodeDomProtocol.value(i);
            if (key.isEmpty()) key = "Other";
        } else {
            key = clusterKeyForAddr(m_nodes[i].rawAddr);
        }
        if (!keyToCluster.contains(key)) {
            Cluster cl;
            cl.label = key;
            if (m_wifiMode) {
                cl.color = wifiClusterColor(key);
            } else if (m_nodeColorMode == NODECOLOR_FUNCTION) {
                if      (key == "Remote Access")     cl.color = serviceCategoryColor(SC_REMOTE);
                else if (key == "Interactive Shell")  cl.color = serviceCategoryColor(SC_INTERACTIVE);
                else if (key == "Messaging")          cl.color = serviceCategoryColor(SC_MESSAGING);
                else if (key == "File Transfer")      cl.color = serviceCategoryColor(SC_FILETRANSFER);
                else                                  cl.color = m_darkTheme ? QColor(100,100,100) : QColor(150,150,150);
            } else if (m_nodeColorMode == NODECOLOR_ROLE) {
                if (key == "External / Internet")
                    cl.color = m_darkTheme ? QColor(220,100, 80) : QColor(180, 55, 35);
                else if (key == "Broadcast / Multicast")
                    cl.color = m_darkTheme ? QColor(200,160, 64) : QColor(160,110, 10);
                else if (key == "MAC / Layer-2")
                    cl.color = m_darkTheme ? QColor(160,100,200) : QColor(110, 55,155);
                else {
                    /* Assign a clearly distinct colour per RFC1918 range so sub-blobs
                     * pop out from the blue "Internal" super-cluster background.
                     * 10.x → amber   172.x → green   192.168.x → teal   fe80 → cyan
                     * Custom / other → cycles through a multi-colour palette. */
                    (void)internalSubnetCount; /* suppress unused-variable warning */
                    if (key.startsWith("10."))
                        cl.color = m_darkTheme ? QColor(220,135, 40) : QColor(190,100, 10);
                    else if (key.startsWith("172."))
                        cl.color = m_darkTheme ? QColor( 55,175, 85) : QColor( 25,145, 55);
                    else if (key.startsWith("192.168."))
                        cl.color = m_darkTheme ? QColor( 30,185,165) : QColor( 10,150,130);
                    else if (key.startsWith("fe80"))
                        cl.color = m_darkTheme ? QColor( 75,205,230) : QColor( 35,170,200);
                    else {
                        /* Custom subnet — use palette colour by key hash */
                        cl.color = clusterPaletteColor(key);
                    }
                }
            } else {
                cl.color = clusterPaletteColor(key);
            }
            keyToCluster[key] = (int)m_clusters.size();
            m_clusters.append(cl);
        }
        m_clusters[keyToCluster[key]].nodeIndices.append(i);
    }

    /* ── Step 2: sort clusters by node count descending ── */
    std::sort(m_clusters.begin(), m_clusters.end(), [](const Cluster &a, const Cluster &b) {
        return a.nodeIndices.size() > b.nodeIndices.size();
    });

    /* ── Step 3: place cluster centres ── */
    int nCl = (int)m_clusters.size();
    QList<QPointF> centres(nCl);
    QPointF ctr(margin + W / 2.0, margin + H / 2.0);

    if (nCl == 1) {
        centres[0] = ctr;
    } else if (!m_wifiMode && m_nodeColorMode == NODECOLOR_ROLE) {
        /* Separate internal subnets (left) from External / special (right).
         * Internal subnets form a sub-ring in the left half; External cluster
         * sits in the right half so the two groups are clearly distinct. */
        QList<int> intIdx, extIdx;
        for (int ci = 0; ci < nCl; ci++) {
            const QString &lbl = m_clusters[ci].label;
            if (lbl == "External / Internet" ||
                lbl == "Broadcast / Multicast" ||
                lbl == "MAC / Layer-2")
                extIdx.append(ci);
            else
                intIdx.append(ci);
        }
        qreal halfW = W * 0.25;
        QPointF intCtr(ctr.x() - halfW, ctr.y());
        QPointF extCtr(ctr.x() + halfW * 1.2, ctr.y());

        /* Internal subnets */
        int nInt = intIdx.size();
        if (nInt == 1) {
            centres[intIdx[0]] = intCtr;
        } else {
            qreal r = qMin(W, H) * 0.20;
            for (int j = 0; j < nInt; j++) {
                qreal a = 2.0 * M_PI * j / nInt - M_PI / 2.0;
                centres[intIdx[j]] = QPointF(intCtr.x() + r * qCos(a),
                                             intCtr.y() + r * qSin(a));
            }
        }
        /* External / special clusters */
        int nExt = extIdx.size();
        if (nExt == 1) {
            centres[extIdx[0]] = extCtr;
        } else {
            qreal r = qMin(W, H) * 0.15;
            for (int j = 0; j < nExt; j++) {
                qreal a = 2.0 * M_PI * j / nExt - M_PI / 2.0;
                centres[extIdx[j]] = QPointF(extCtr.x() + r * qCos(a),
                                             extCtr.y() + r * qSin(a));
            }
        }
    } else {
        /* Default: arrange all cluster centres on a ring */
        qreal clRing = qMin(W, H) * 0.30;
        for (int ci = 0; ci < nCl; ci++) {
            qreal angle = 2.0 * M_PI * ci / nCl - M_PI / 2.0;
            centres[ci] = QPointF(ctr.x() + clRing * qCos(angle),
                                  ctr.y() + clRing * qSin(angle));
        }
    }

    /* ── Step 4: position nodes within each cluster ── */
    qreal baseR = m_nodes[0].hexRadius;  /* same for all nodes */
    for (int ci = 0; ci < nCl; ci++) {
        QList<int> &idxs = m_clusters[ci].nodeIndices;
        int cn = (int)idxs.size();
        QPointF cc = centres[ci];

        if (cn == 1) {
            m_nodes[idxs[0]].pos = cc;
        } else {
            /* Mini-circle radius: enough spacing to avoid hex overlap */
            qreal minSep  = baseR * 2.5 + 6.0;
            qreal miniR   = qMax(minSep, minSep * cn / (2.0 * M_PI));
            /* Cap so clusters don't collide on screen */
            miniR = qMin(miniR, qMin(W, H) * 0.17);
            for (int j = 0; j < cn; j++) {
                qreal angle = 2.0 * M_PI * j / cn - M_PI / 2.0;
                m_nodes[idxs[j]].pos = QPointF(cc.x() + miniR * qCos(angle),
                                                cc.y() + miniR * qSin(angle));
            }
        }
    }

    /* ── Step 5: compute inflated bounding rect for each cluster ── */
    for (Cluster &cl : m_clusters) {
        if (cl.nodeIndices.isEmpty()) continue;
        qreal xmin =  1e9, xmax = -1e9;
        qreal ymin =  1e9, ymax = -1e9;
        for (int ni : cl.nodeIndices) {
            qreal x = m_nodes[ni].pos.x();
            qreal y = m_nodes[ni].pos.y();
            xmin = qMin(xmin, x); xmax = qMax(xmax, x);
            ymin = qMin(ymin, y); ymax = qMax(ymax, y);
        }
        qreal pad  = baseR + 24.0;   /* hex radius + visual padding */
        qreal topPad = pad + 16.0;   /* extra headroom for the label */
        cl.bounds = QRectF(xmin - pad,      ymin - topPad,
                           (xmax - xmin) + 2 * pad,
                           (ymax - ymin) + pad + topPad);
    }

    /* ── Step 6: for NODECOLOR_ROLE, wrap all internal subnet clusters in a
     *             single "Internal" super-blob drawn behind the sub-blobs. ── */
    if (!m_wifiMode && m_nodeColorMode == NODECOLOR_ROLE) {
        qreal xmin =  1e9, xmax = -1e9;
        qreal ymin =  1e9, ymax = -1e9;
        bool  any  = false;
        for (const Cluster &cl : m_clusters) {
            if (cl.label == "External / Internet" ||
                cl.label == "Broadcast / Multicast" ||
                cl.label == "MAC / Layer-2") continue;
            xmin = qMin(xmin, cl.bounds.left());
            xmax = qMax(xmax, cl.bounds.right());
            ymin = qMin(ymin, cl.bounds.top());
            ymax = qMax(ymax, cl.bounds.bottom());
            any = true;
        }
        if (any) {
            qreal pad = 28.0;
            SuperCluster sc;
            sc.label  = "Internal";
            sc.color  = m_darkTheme ? QColor(50, 100, 160) : QColor(30, 75, 135);
            sc.bounds = QRectF(xmin - pad, ymin - pad - 18.0,
                               (xmax - xmin) + 2 * pad,
                               (ymax - ymin) + 2 * pad + 18.0);
            m_superClusters.append(sc);
        }
    }
}

/* Concentric layout: nodes in concentric rings sorted by degree.
 * Highest-degree nodes in the innermost ring; isolated nodes in the outermost. */
void GraphWidget::layoutConcentric()
{
    int N = (int)m_nodes.size();
    if (N == 0) return;
    const qreal margin = 60.0;
    qreal W = qMax(200.0, (qreal)width()  - 2 * margin);
    qreal H = qMax(200.0, (qreal)height() - 2 * margin);
    QPointF centre(margin + W / 2.0, margin + H / 2.0);

    /* Compute degree for every node */
    QHash<int, int> degree;
    for (const GraphEdge &e : m_edges) {
        degree[e.srcIdx]++;
        degree[e.dstIdx]++;
    }

    /* Sort nodes by degree descending */
    QList<int> order;
    for (int i = 0; i < N; i++) order.append(i);
    std::sort(order.begin(), order.end(), [&degree](int a, int b) {
        return degree.value(a, 0) > degree.value(b, 0);
    });

    /* Distribute into rings.  Innermost ring holds the fewest nodes (1 or
     * a small number); outer rings grow so angular spacing stays readable. */
    qreal minR     = qMin(W, H) * 0.10;   /* first ring radius */
    qreal ringStep = qMin(W, H) * 0.15;   /* radius increment per ring */

    int placed = 0;
    int ring   = 0;
    while (placed < N) {
        qreal r = (ring == 0) ? 0.0 : (minR + ringStep * (ring - 1));

        /* Ring 0 = single node at centre if degree is much higher than next */
        int cap;
        if (ring == 0) {
            /* Put only the absolute hub at centre if it has ≥2x the degree of
             * the second node; otherwise start with a ring. */
            int d0 = degree.value(order[0], 0);
            int d1 = (N > 1) ? degree.value(order[1], 0) : 0;
            if (N == 1 || d0 >= 2 * qMax(d1, 1)) {
                cap = 1;
            } else {
                /* Skip ring-0 centre; start with ring 1 */
                ring = 1;
                r    = minR;
                cap  = qMax(4, (int)qFloor(2.0 * M_PI * r / 70.0));
            }
        } else {
            cap = qMax(4, (int)qFloor(2.0 * M_PI * r / 70.0));
        }
        cap = qMin(cap, N - placed);

        if (cap == 1 || r == 0.0) {
            m_nodes[order[placed]].pos = centre;
        } else {
            for (int i = 0; i < cap; i++) {
                qreal angle = 2.0 * M_PI * i / cap - M_PI / 2.0;
                m_nodes[order[placed + i]].pos =
                    QPointF(centre.x() + r * qCos(angle),
                            centre.y() + r * qSin(angle));
            }
        }
        placed += cap;
        ring++;
    }
}

/* Hierarchical layout: four tiers arranged top-to-bottom.
 *
 *  Tier 0 (top)    — External / Internet nodes (non-RFC-1918, non-broadcast)
 *  Tier 1          — Gateway candidates: nodes with edges to both external
 *                    and internal addresses
 *  Tier 2          — Internal servers: RFC-1918 nodes accepting connections
 *                    on well-known ports (dst port < 1024 seen)
 *  Tier 3 (bottom) — Remaining clients / internal hosts
 */
void GraphWidget::layoutHierarchical()
{
    int N = (int)m_nodes.size();
    if (N == 0) return;
    const qreal margin  = 60.0;
    const qreal tierPad = 30.0;   /* extra vertical padding at top/bottom */
    qreal W = qMax(200.0, (qreal)width()  - 2 * margin);
    qreal H = qMax(200.0, (qreal)height() - 2 * margin);

    /* ── Assign each node to a tier ── */
    QVector<int> tier(N, 3);   /* default: client */

    /* Identify which nodes have external vs. internal neighbours */
    QVector<bool> hasExternalNeighbour(N, false);
    QVector<bool> hasInternalNeighbour(N, false);

    for (const GraphEdge &e : m_edges) {
        int si = e.srcIdx, di = e.dstIdx;
        if (si < 0 || si >= N || di < 0 || di >= N) continue;
        bool srcExt = !isRFC1918(m_nodes[si].rawAddr);
        bool dstExt = !isRFC1918(m_nodes[di].rawAddr);
        if (srcExt) hasExternalNeighbour[di] = true;
        else        hasInternalNeighbour[di] = true;
        if (dstExt) hasExternalNeighbour[si] = true;
        else        hasInternalNeighbour[si] = true;
    }

    /* Determine if a node is an internal server (accepts well-known ports) */
    /* Build: for each node, check if it is the destination of any well-known port (<1024) */
    QVector<bool> isServer(N, false);
    for (const GraphEdge &e : m_edges) {
        if (!e.pair || !e.pair->dst_ports) continue;
        int di = e.dstIdx;
        if (di < 0 || di >= N || !isRFC1918(m_nodes[di].rawAddr)) continue;
        /* Iterate the dst_ports hash table; port is the GUINT key */
        GHashTableIter iter;
        gpointer key, val;
        g_hash_table_iter_init(&iter, e.pair->dst_ports);
        while (g_hash_table_iter_next(&iter, &key, &val)) {
            guint port = GPOINTER_TO_UINT(key);
            if (port > 0 && port < 1024) { isServer[di] = true; break; }
        }
    }

    for (int i = 0; i < N; i++) {
        bool ext = !isRFC1918(m_nodes[i].rawAddr);
        if (ext) {
            tier[i] = 0;  /* External */
        } else if (hasExternalNeighbour[i] && hasInternalNeighbour[i]) {
            tier[i] = 1;  /* Gateway */
        } else if (isServer[i]) {
            tier[i] = 2;  /* Internal server */
        } else {
            tier[i] = 3;  /* Client */
        }
    }

    /* Sort nodes within each tier by traffic descending */
    QList<QList<int>> tiers(4);
    for (int i = 0; i < N; i++) tiers[tier[i]].append(i);
    for (int t = 0; t < 4; t++) {
        std::sort(tiers[t].begin(), tiers[t].end(), [this](int a, int b) {
            return m_nodes[a].totalBytes > m_nodes[b].totalBytes;
        });
    }

    /* ── Collapse empty tiers — distribute active tiers evenly ── */
    QList<int> activeTiers;
    for (int t = 0; t < 4; t++) if (!tiers[t].isEmpty()) activeTiers.append(t);
    int nTiers = (int)activeTiers.size();
    if (nTiers == 0) return;

    qreal usableH = H - 2 * tierPad;
    qreal tierSpacing = (nTiers > 1) ? usableH / (nTiers - 1) : 0.0;

    for (int ti = 0; ti < nTiers; ti++) {
        int t    = activeTiers[ti];
        int cnt  = (int)tiers[t].size();
        qreal y  = margin + tierPad + (nTiers > 1 ? ti * tierSpacing : usableH / 2.0);
        qreal xStep = (cnt > 1) ? W / (cnt - 1) : 0.0;
        for (int j = 0; j < cnt; j++) {
            qreal x = (cnt == 1) ? margin + W / 2.0 : margin + j * xStep;
            m_nodes[tiers[t][j]].pos = QPointF(x, y);
        }
    }
}

/* Radial (BFS) layout: most-connected node at centre; BFS outward.
 * Ring N = nodes at BFS depth N from the root.  Nodes not reachable from
 * the root (isolated sub-graphs) are placed in the outermost ring. */
void GraphWidget::layoutRadial()
{
    int N = (int)m_nodes.size();
    if (N == 0) return;
    const qreal margin = 60.0;
    qreal W = qMax(200.0, (qreal)width()  - 2 * margin);
    qreal H = qMax(200.0, (qreal)height() - 2 * margin);
    QPointF centre(margin + W / 2.0, margin + H / 2.0);

    /* Find root = node with highest degree */
    QHash<int, QList<int>> adj;  /* adjacency list (undirected) */
    for (const GraphEdge &e : m_edges) {
        if (e.srcIdx < 0 || e.srcIdx >= N || e.dstIdx < 0 || e.dstIdx >= N) continue;
        adj[e.srcIdx].append(e.dstIdx);
        adj[e.dstIdx].append(e.srcIdx);
    }

    int rootIdx = 0;
    int maxDeg  = -1;
    for (int i = 0; i < N; i++) {
        int d = adj.value(i).size();
        if (d > maxDeg) { maxDeg = d; rootIdx = i; }
    }

    /* BFS from root */
    QVector<int> depth(N, -1);
    QList<QList<int>> rings;
    QQueue<int> queue;
    depth[rootIdx] = 0;
    queue.enqueue(rootIdx);
    rings.append(QList<int>{rootIdx});

    while (!queue.isEmpty()) {
        int cur = queue.dequeue();
        for (int nb : adj.value(cur)) {
            if (depth[nb] == -1) {
                depth[nb] = depth[cur] + 1;
                /* Extend rings list if needed */
                while (rings.size() <= depth[nb]) rings.append(QList<int>());
                rings[depth[nb]].append(nb);
                queue.enqueue(nb);
            }
        }
    }

    /* Nodes not reachable from root → add to extra outermost ring */
    QList<int> unreachable;
    for (int i = 0; i < N; i++) if (depth[i] == -1) unreachable.append(i);
    if (!unreachable.isEmpty()) rings.append(unreachable);

    /* Place rings */
    int nRings = (int)rings.size();
    qreal ringStep = qMin(W, H) / 2.0 / qMax(nRings, 2);
    ringStep = qMin(ringStep, 110.0);  /* cap so nodes don't fly off-screen */

    for (int ri = 0; ri < nRings; ri++) {
        const QList<int> &ring = rings[ri];
        int cnt = (int)ring.size();
        if (cnt == 0) continue;

        if (ri == 0) {
            /* Root at centre */
            m_nodes[ring[0]].pos = centre;
            continue;
        }

        qreal r = ri * ringStep;
        for (int j = 0; j < cnt; j++) {
            qreal angle = 2.0 * M_PI * j / cnt - M_PI / 2.0;
            m_nodes[ring[j]].pos = QPointF(centre.x() + r * qCos(angle),
                                           centre.y() + r * qSin(angle));
        }
    }
}

/* Push any node whose centre overlaps the legend area upward / rightward
 * so the bottom-left legend is always readable.
 * Called from applyLayout() for every layout mode. */
void GraphWidget::protectLegendArea()
{
    if (m_nodes.isEmpty()) return;

    /* Compute actual legend item count */
    int items = 0;
    switch (m_nodeColorMode) {
        case NODECOLOR_SERVICE:
            items = (int)m_legendServices.size()
                  + ((m_legendHasUnknown || m_legendServices.isEmpty()) ? 1 : 0);
            break;
        case NODECOLOR_ROLE:     items = 4; break;
        case NODECOLOR_FUNCTION: items = 5; break; /* 4 service categories + Other */
        case NODECOLOR_PROTOCOL: items = 1; break;
    }
    /* Each item ≈ 16 px, plus a small font-height header and padding */
    qreal legH = items * 16.0 + 24.0;
    qreal legW = 195.0;                 /* conservative max label width */
    m_legendRect = QRectF(0, (qreal)height() - legH, legW, legH);

    /* Expand by node radius for the intersection test */
    qreal r = m_nodes.isEmpty() ? 12.0 : m_nodes[0].hexRadius;
    QRectF danger = m_legendRect.adjusted(-r, -r, r, r);

    for (GraphNode &n : m_nodes) {
        if (!danger.contains(n.pos)) continue;

        /* Push up enough to clear the legend, and right enough if still inside */
        qreal clearTop = m_legendRect.top() - r - 4.0;
        n.pos.setY(qMax(r + 4.0, clearTop));
        /* If still horizontally inside the legend strip, push right too */
        if (n.pos.x() < m_legendRect.right() + r)
            n.pos.setX(m_legendRect.right() + r + 4.0);
        /* Clamp to widget */
        n.pos.setX(qBound(r + 2.0, n.pos.x(), (qreal)width()  - r - 2.0));
        n.pos.setY(qBound(r + 2.0, n.pos.y(), (qreal)height() - r - 2.0));
    }
}

/* ─────────────────────────────────────────────────────────────────────── *
 *  Visual helpers
 * ─────────────────────────────────────────────────────────────────────── */

bool GraphWidget::isRFC1918(const QString &ip) const
{
    /* Fast-path for built-in RFC1918 / loopback / link-local ranges */
    if (ip.startsWith("10.") || ip.startsWith("192.168.") ||
        ip.startsWith("127.") || ip.startsWith("169.254.") ||
        ip.startsWith("::1")  || ip.startsWith("fc") || ip.startsWith("fd"))
        return true;
    if (ip.startsWith("172.")) {
        QStringList parts = ip.split('.');
        if (parts.size() >= 2) {
            bool ok; int second = parts[1].toInt(&ok);
            if (ok && second >= 16 && second <= 31) return true;
        }
    }
    /* Also check user-added custom subnets */
    QStringList parts = ip.split('.');
    if (parts.size() == 4) {
        bool ok[4];
        int oct[4];
        for (int i = 0; i < 4; i++) oct[i] = parts[i].toInt(&ok[i]);
        if (ok[0] && ok[1] && ok[2] && ok[3]) {
            quint32 addr32 = ((quint32)oct[0] << 24) | ((quint32)oct[1] << 16) |
                             ((quint32)oct[2] << 8)  |  (quint32)oct[3];
            for (const InternalSubnet &sn : m_internalSubnets) {
                if (sn.builtIn) continue; /* already handled above */
                QStringList pp = sn.prefix.split('.');
                if (pp.size() != 4) continue;
                bool pok[4]; quint32 net = 0;
                for (int i = 0; i < 4; i++) { int v = pp[i].toInt(&pok[i]); net |= ((quint32)v << (24 - 8*i)); }
                if (!pok[0]||!pok[1]||!pok[2]||!pok[3]) continue;
                quint32 mask = sn.bits > 0 ? (~0u << (32 - sn.bits)) : 0;
                if ((addr32 & mask) == (net & mask)) return true;
            }
        }
    }
    return false;
}

QColor GraphWidget::serviceColor(quint16 port) const
{
    return portServiceColor(port);
}

QColor GraphWidget::serviceCategoryColor(ServiceCategory cat) const
{
    switch (cat) {
        case SC_REMOTE:       return m_darkTheme ? QColor(210,  55,  55) : QColor(180,  30,  30); /* crimson  */
        case SC_INTERACTIVE:  return m_darkTheme ? QColor(240, 140,  40) : QColor(210, 100,  10); /* orange   */
        case SC_MESSAGING:    return m_darkTheme ? QColor( 30, 200, 170) : QColor( 15, 155, 130); /* teal     */
        case SC_FILETRANSFER: return m_darkTheme ? QColor( 60, 195,  95) : QColor( 30, 155,  65); /* green    */
        default:              return QColor(120, 120, 120);
    }
}

QColor GraphWidget::roleColor(const GraphNode &node) const
{
    const QString &addr = node.rawAddr;
    if (addr.startsWith("224.") || addr.startsWith("239.") ||
        addr.startsWith("ff0")  || addr.startsWith("ff02") ||
        addr == "255.255.255.255" || addr.endsWith(".255"))
        return m_darkTheme ? QColor(200, 160, 64) : QColor(160, 110, 10);  /* broadcast/multicast — amber */
    if (addr.count(':') == 5 && addr.length() == 17)
        return m_darkTheme ? QColor(160, 100, 200) : QColor(110, 55, 155); /* MAC / Layer-2 — purple */
    if (isRFC1918(addr) || addr.startsWith("fe80"))
        return m_darkTheme ? QColor(70, 130, 180) : QColor(41, 98, 163);   /* internal — blue */
    if (addr.contains('.') || addr.contains(':'))
        return m_darkTheme ? QColor(220, 100, 80) : QColor(180, 55, 35);   /* external — red */
    return m_darkTheme ? QColor(140, 140, 140) : QColor(100, 100, 100);
}

/* ─── classifyServiceCategory ────────────────────────────────────────────── *
 * Determines the functional role of a node from the set of destination ports
 * it receives connections on (server-side only).  Priority: Remote > Interactive
 * > Messaging > Filetransfer.  Returns SC_NONE if no match.
 * ─────────────────────────────────────────────────────────────────────────── */
GraphWidget::ServiceCategory
GraphWidget::classifyServiceCategory(const QHash<quint16, quint64> &dstPorts)
{
    if (dstPorts.isEmpty()) return SC_NONE;

    auto has = [&](quint16 p) { return dstPorts.contains(p); };

    /* Remote-desktop / remote-access servers */
    if (has(3389) ||                         /* RDP           */
        has(5900) || has(5901) || has(5902)|| /* VNC           */
        has(5930) ||                          /* SPICE         */
        has(1494) || has(2598) ||             /* Citrix ICA    */
        has(7070))                            /* AnyDesk       */
        return SC_REMOTE;

    /* Interactive-shell servers */
    if (has(22)  ||                           /* SSH / SFTP    */
        has(23)  ||                           /* Telnet        */
        has(512) || has(513) || has(514))     /* rexec/rlogin/rsh */
        return SC_INTERACTIVE;

    /* Messaging / real-time communications */
    if (has(5060) || has(5061) ||             /* SIP / SIP-TLS */
        has(5222) || has(5223) ||             /* XMPP          */
        has(6667) || has(6697) ||             /* IRC / IRC-TLS */
        has(3478) || has(3479) ||             /* STUN / TURN   */
        has(1883) || has(8883))               /* MQTT          */
        return SC_MESSAGING;

    /* File-transfer servers */
    if (has(445) || has(139) ||               /* SMB / NetBIOS */
        has(2049) ||                          /* NFS           */
        has(21)  || has(20)  ||               /* FTP           */
        has(69)  ||                           /* TFTP          */
        has(873))                             /* rsync         */
        return SC_FILETRANSFER;

    return SC_NONE;
}

/* ─── highRiskColor ──────────────────────────────────────────────────────── *
 * Returns an edge colour reflecting the highest risk port seen in the pair.
 *   Critical (deep red)  — Telnet, FTP, rsh/rexec, TFTP, native X11, VNC
 *   High     (orange)    — RDP, WinRM, AnyDesk
 *   Elevated (yellow)    — SSH, MQTT plain, SNMP
 *   VPN/TOR  (violet)    — OpenVPN, WireGuard, L2TP, IPSec, TOR
 *   Normal   (grey)      — everything else
 * ─────────────────────────────────────────────────────────────────────────── */
QColor GraphWidget::highRiskColor(comm_pair_t *pair) const
{
    if (!pair || !pair->dst_ports) {
        return m_darkTheme ? QColor(100, 100, 100) : QColor(130, 130, 130);
    }

    int maxRisk = 0;  /* 0=normal 1=elevated 2=high 3=vpn/tor 4=critical */

    GHashTableIter iter;
    gpointer key, value;
    g_hash_table_iter_init(&iter, pair->dst_ports);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        quint16 p = (quint16)(uintptr_t)key;
        int risk = 0;

        /* Critical: cleartext remote access, plaintext management */
        if (p == 23 || p == 21 || p == 20 ||          /* Telnet, FTP */
            p == 512 || p == 513 || p == 514 ||         /* rexec/rlogin/rsh */
            p == 69  ||                                 /* TFTP */
            p == 5900 || p == 5901 || p == 5902 ||      /* VNC (often no/weak auth) */
            (p >= 6000 && p <= 6063))                   /* native X11 */
            risk = 4;
        /* High: remote-desktop, management protocols */
        else if (p == 3389 ||                           /* RDP */
                 p == 5985 || p == 5986 ||              /* WinRM */
                 p == 7070)                             /* AnyDesk */
            risk = 2;
        /* VPN / TOR */
        else if (p == 1194 ||                           /* OpenVPN */
                 p == 51820 ||                          /* WireGuard */
                 p == 1701  ||                          /* L2TP */
                 p == 500   || p == 4500 ||             /* IKE / IPSec NAT-T */
                 p == 9001  || p == 9030 ||             /* TOR relay / dir */
                 p == 9050  || p == 9150)               /* TOR SOCKS proxy */
            risk = 3;
        /* Elevated: encrypted but notable attack surface */
        else if (p == 22   ||                           /* SSH */
                 p == 1883 ||                           /* MQTT plain */
                 p == 161  || p == 162)                 /* SNMP v1/v2 */
            risk = 1;

        if (risk > maxRisk) maxRisk = risk;
    }

    switch (maxRisk) {
        case 4: return m_darkTheme ? QColor(210,  35,  35) : QColor(185,  20,  20); /* critical — deep red  */
        case 3: return m_darkTheme ? QColor(160,  80, 210) : QColor(120,  50, 175); /* VPN/TOR  — violet    */
        case 2: return m_darkTheme ? QColor(235, 110,  25) : QColor(205,  80,  10); /* high     — orange    */
        case 1: return m_darkTheme ? QColor(220, 185,  30) : QColor(185, 150,  10); /* elevated — yellow    */
        default:return m_darkTheme ? QColor(100, 100, 100) : QColor(140, 140, 140); /* normal   — grey      */
    }
}

QColor GraphWidget::protocolColor(const gchar *proto) const
{
    guint32 rgb = packet_analyzer_get_protocol_color(proto ? proto : "");
    return QColor((rgb >> 16) & 0xFF, (rgb >> 8) & 0xFF, rgb & 0xFF);
}

/* ─────────────────────────────────────────────────────────────────────── *
 *  Drawing helpers
 * ─────────────────────────────────────────────────────────────────────── */

QPolygonF GraphWidget::makeHex(const QPointF &center, qreal radius)
{
    QPolygonF hex;
    for (int i = 0; i < 6; i++) {
        qreal angle = (M_PI / 3.0) * i;
        hex << QPointF(center.x() + radius * qCos(angle),
                       center.y() + radius * qSin(angle));
    }
    return hex;
}

/* Same as CircleWidget::getLineHexagonIntersection */
QPointF GraphWidget::hexEdgeIntersect(const QPointF &from, const QPointF &to,
                                      const QPointF &center, qreal radius)
{
    QPointF dir = to - from;
    qreal len = qSqrt(dir.x()*dir.x() + dir.y()*dir.y());
    if (len == 0) return center;
    QPointF u = dir / len;
    QPointF ts = from - center;
    qreal b = 2.0 * (ts.x()*u.x() + ts.y()*u.y());
    qreal c = ts.x()*ts.x() + ts.y()*ts.y() - radius*radius;
    qreal disc = b*b - 4.0*c;
    if (disc < 0) return center;
    qreal t = (-b + qSqrt(disc)) / 2.0;
    if (t < 0) t = (-b - qSqrt(disc)) / 2.0;
    return from + u * t;
}

/**
 * Draw the double-hexagon node identical to CircleWidget::drawNode().
 *   drawOuterOnly=true: only outer ring (first pass)
 *   drawOuterOnly=false: both rings
 */
void GraphWidget::drawHexNode(QPainter &p, const GraphNode &node,
                               bool drawOuterOnly, bool /*highlighted*/, bool blinkOn) const
{
    QColor col = node.color;
    if (blinkOn) col = QColor(255, 0, 0);
    qreal r = node.hexRadius;
    QPointF c = node.pos;

    if (!drawOuterOnly) {
        /* Outer hexagon: coloured outline, transparent fill */
        p.setPen(QPen(col, blinkOn ? 3.5 : 2.5));
        p.setBrush(Qt::NoBrush);
        p.drawPolygon(makeHex(c, r));
    }

    /* Inner hexagon (60% radius): semi-transparent filled */
    qreal ir = r * 0.6;
    QColor fill(col.red(), col.green(), col.blue(), blinkOn ? 220 : 180);
    p.setPen(QPen(col.lighter(150), blinkOn ? 2.8 : 2.0));
    p.setBrush(fill);
    p.drawPolygon(makeHex(c, ir));

    if (!drawOuterOnly) {
        /* Label: white text with black outline, below the node */
        int dim = qMin(width(), height());
        int fs;
        if      (dim < 400)  fs = 7;
        else if (dim < 600)  fs = 8;
        else if (dim < 800)  fs = 9;
        else if (dim < 1000) fs = 10;
        else                 fs = 11;

        QFont font = p.font();
        font.setPointSize(fs);
        font.setBold(true);
        p.setFont(font);

        QString lbl = node.displayLabel;
        if (lbl.length() > 22) lbl = lbl.left(20) + QChar(0x2026);

        QFontMetrics fm(font);
        qreal tx = c.x() - fm.horizontalAdvance(lbl) / 2.0;
        qreal ty = c.y() + r + 18;
        QPainterPath tp;
        tp.addText(tx, ty, font, lbl);
        /* Black outline */
        p.setPen(QPen(QColor(0,0,0), 4, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
        p.setBrush(Qt::NoBrush);
        p.drawPath(tp);
        /* White fill */
        p.setPen(Qt::NoPen);
        p.setBrush(QColor(255,255,255));
        p.drawPath(tp);
    }
}

void GraphWidget::drawEdge(QPainter &p, const GraphEdge &edge,
                            bool hovered, bool selected) const
{
    if (edge.srcIdx < 0 || edge.dstIdx < 0) return;
    if (edge.srcIdx >= m_nodes.size() || edge.dstIdx >= m_nodes.size()) return;

    const QPointF src = m_nodes[edge.srcIdx].pos;
    const QPointF dst = m_nodes[edge.dstIdx].pos;
    qreal srcR = m_nodes[edge.srcIdx].hexRadius;
    qreal dstR = m_nodes[edge.dstIdx].hexRadius;

    QPointF p1 = hexEdgeIntersect(src, dst, src, srcR + 1.0);
    QPointF p2 = hexEdgeIntersect(dst, src, dst, dstR + 1.0);
    if ((p2 - p1).manhattanLength() < 4.0) return;

    QColor color = selected ? QColor(255, 200, 0) : edge.color;
    if (hovered) color = color.lighter(140);
    color.setAlphaF(selected ? 1.0 : edge.opacity * (hovered ? 1.4 : 1.0));
    qreal thickness = edge.thickness * (hovered || selected ? 1.6 : 1.0);
    if (selected && thickness < 2.5) thickness = 2.5;

    Qt::PenStyle style = edge.bidirectional ? Qt::SolidLine : Qt::DashLine;
    if (selected) style = Qt::DashLine;
    p.setPen(QPen(color, thickness, style, Qt::RoundCap));
    p.setBrush(Qt::NoBrush);
    p.drawLine(p1, p2);
}

/* ─────────────────────────────────────────────────────────────────────── *
 *  Hit testing
 * ─────────────────────────────────────────────────────────────────────── */

int GraphWidget::hitTestNode(const QPointF &pt) const
{
    for (int i = (int)m_nodes.size() - 1; i >= 0; i--) {
        const GraphNode &n = m_nodes[i];
        QPointF d = pt - n.pos;
        if (d.x()*d.x() + d.y()*d.y() <= (n.hexRadius + 5) * (n.hexRadius + 5))
            return i;
    }
    return -1;
}

int GraphWidget::hitTestEdge(const QPointF &pt) const
{
    const qreal kThr = 7.0;
    int best = -1; qreal bestD = kThr;
    for (int i = 0; i < (int)m_edges.size(); i++) {
        const GraphEdge &e = m_edges[i];
        if (e.srcIdx < 0 || e.dstIdx < 0 ||
            e.srcIdx >= m_nodes.size() || e.dstIdx >= m_nodes.size()) continue;
        QPointF a = m_nodes[e.srcIdx].pos, b = m_nodes[e.dstIdx].pos;
        QPointF ab = b - a;
        qreal len2 = ab.x()*ab.x() + ab.y()*ab.y();
        if (len2 < 1.0) continue;
        qreal t = qBound(0.0, ((pt.x()-a.x())*ab.x() + (pt.y()-a.y())*ab.y()) / len2, 1.0);
        QPointF cl = a + ab * t;
        QPointF diff = pt - cl;
        qreal d = qSqrt(diff.x()*diff.x() + diff.y()*diff.y());
        if (d < bestD) { bestD = d; best = i; }
    }
    return best;
}

/* ─────────────────────────────────────────────────────────────────────── *
 *  Events
 * ─────────────────────────────────────────────────────────────────────── */

void GraphWidget::paintEvent(QPaintEvent *event)
{
    Q_UNUSED(event)
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing);
    p.fillRect(rect(), QColor(0, 0, 0));  /* Always black like circle view */

    if (m_nodes.isEmpty()) {
        p.setPen(QColor(100, 100, 105));
        QFont f; f.setPointSize(13); p.setFont(f);
        p.drawText(rect(), Qt::AlignCenter,
            "Graph view\nLoad a capture and click Reload");
        return;
    }

    /* ── Legend filter: pre-compute per-edge and per-node faded state ── */
    m_legendHitRects.clear();
    const int nNodes = (int)m_nodes.size();
    const int nEdges = (int)m_edges.size();
    QVector<bool> nodeFaded(nNodes, false);
    QVector<bool> edgeFaded(nEdges, false);
    if (m_legendFilterColor.isValid()) {
        if (m_legendFilterIsNode && m_legendFilterPort > 0) {
            /* Service / port legend: fade edges that don't carry the filtered port;
             * fade nodes that have no surviving (non-faded) edge.
             * This correctly highlights all traffic on a given service regardless
             * of whether that port is the node's single dominant port. */
            auto pairHasPort = [](comm_pair_t *p, quint16 port) -> bool {
                if (!p || !p->dst_ports) return false;
                return g_hash_table_lookup(p->dst_ports,
                           GUINT_TO_POINTER((guint)port)) != nullptr;
            };
            for (int i = 0; i < nEdges; i++) {
                const GraphEdge &e = m_edges[i];
                edgeFaded[i] = !pairHasPort(e.pair,        m_legendFilterPort)
                            && !pairHasPort(e.reversePair, m_legendFilterPort);
            }
            /* A node is faded if every one of its edges is faded */
            for (int ni = 0; ni < nNodes; ni++) {
                bool anyVisible = false;
                for (int ei = 0; ei < nEdges; ei++) {
                    if (edgeFaded[ei]) continue;
                    const GraphEdge &e = m_edges[ei];
                    if (e.srcIdx == ni || e.dstIdx == ni) { anyVisible = true; break; }
                }
                nodeFaded[ni] = !anyVisible;
            }
        } else if (m_legendFilterIsNode) {
            /* Role / Other legend: fade nodes whose colour doesn't match; fade edges where
             * neither endpoint matches. */
            for (int i = 0; i < nNodes; i++)
                nodeFaded[i] = (m_nodes[i].color != m_legendFilterColor);
            for (int i = 0; i < nEdges; i++) {
                const GraphEdge &e = m_edges[i];
                bool sOk = e.srcIdx >= 0 && e.srcIdx < nNodes && !nodeFaded[e.srcIdx];
                bool dOk = e.dstIdx >= 0 && e.dstIdx < nNodes && !nodeFaded[e.dstIdx];
                edgeFaded[i] = !sOk && !dOk;
            }
        } else {
            /* Edge filter: fade edges whose colour doesn't match; fade nodes that
             * have no matching edge. */
            for (int i = 0; i < nEdges; i++)
                edgeFaded[i] = (m_edges[i].color != m_legendFilterColor);
            for (int ni = 0; ni < nNodes; ni++) {
                bool any = false;
                for (int i = 0; i < nEdges && !any; i++)
                    if (!edgeFaded[i] && (m_edges[i].srcIdx == ni || m_edges[i].dstIdx == ni))
                        any = true;
                nodeFaded[ni] = !any;
            }
        }
    }

    /* ── Apply zoom / pan transform for all world-space drawing ── */
    p.save();
    p.translate(m_panOffset);
    p.scale(m_scale, m_scale);

    /* ── Cluster blobs (behind edges and nodes, only in LAYOUT_CLUSTER) ── */
    if (m_layoutMode == LAYOUT_CLUSTER && !m_clusters.isEmpty()) {
        /* Recompute bounds from current node positions (handles post-resize scaling
         * and node dragging without needing a full relayout). */
        qreal baseR = m_nodes.isEmpty() ? 12.0 : m_nodes[0].hexRadius;
        for (Cluster &cl : m_clusters) {
            if (cl.nodeIndices.isEmpty()) continue;
            qreal xmin =  1e9, xmax = -1e9, ymin =  1e9, ymax = -1e9;
            for (int ni : cl.nodeIndices) {
                qreal x = m_nodes[ni].pos.x(), y = m_nodes[ni].pos.y();
                xmin = qMin(xmin, x); xmax = qMax(xmax, x);
                ymin = qMin(ymin, y); ymax = qMax(ymax, y);
            }
            qreal pad    = baseR + 24.0;
            qreal topPad = pad   + 16.0;
            cl.bounds = QRectF(xmin - pad, ymin - topPad,
                               (xmax - xmin) + 2 * pad,
                               (ymax - ymin) + pad + topPad);
        }

        /* Recompute super-cluster bounds from updated sub-cluster bounds */
        for (SuperCluster &sc : m_superClusters) {
            qreal xmin =  1e9, xmax = -1e9, ymin =  1e9, ymax = -1e9;
            bool any = false;
            for (const Cluster &cl : m_clusters) {
                if (cl.label == "External / Internet" ||
                    cl.label == "Broadcast / Multicast" ||
                    cl.label == "MAC / Layer-2") continue;
                xmin = qMin(xmin, cl.bounds.left());
                xmax = qMax(xmax, cl.bounds.right());
                ymin = qMin(ymin, cl.bounds.top());
                ymax = qMax(ymax, cl.bounds.bottom());
                any = true;
            }
            if (any) {
                qreal pad = 28.0;
                sc.bounds = QRectF(xmin - pad, ymin - pad - 18.0,
                                   (xmax - xmin) + 2 * pad,
                                   (ymax - ymin) + 2 * pad + 18.0);
            }
        }

        /* ── Super-cluster blobs (behind sub-clusters) ── */
        for (int sci = 0; sci < (int)m_superClusters.size(); sci++) {
            const SuperCluster &sc = m_superClusters[sci];
            QColor fill(sc.color.red(), sc.color.green(), sc.color.blue(),
                        m_darkTheme ? 25 : 20);
            QColor border(sc.color.red(), sc.color.green(), sc.color.blue(), 90);
            QPen sp(border, 2.0, Qt::DotLine);
            p.setPen(sp);
            p.setBrush(fill);
            p.drawRoundedRect(sc.bounds, 18, 18);
            p.setPen(QColor(sc.color.red(), sc.color.green(), sc.color.blue(),
                            m_darkTheme ? 200 : 170));
            QFont sf; sf.setPointSize(9); sf.setBold(true); p.setFont(sf);
            p.drawText(QPointF(sc.bounds.left() + 10, sc.bounds.top() + 16),
                       sc.label);
        }

        QFont clf; clf.setPointSize(9); clf.setBold(true);
        QFontMetrics clfm(clf);
        p.setFont(clf);

        for (int ci = 0; ci < (int)m_clusters.size(); ci++) {
            const Cluster &cl = m_clusters[ci];
            if (cl.bounds.isNull() || cl.nodeIndices.isEmpty()) continue;

            bool isBeingDragged = (m_draggedCluster == ci);
            /* Semi-transparent filled rounded rect; brighter when dragged */
            /* Sub-clusters inside a super-cluster get solid borders + stronger fill
             * so they clearly pop out from the super-blob background. */
            bool isInsideSuper = !m_superClusters.isEmpty();
            int fillAlpha   = isBeingDragged ? 85 : (isInsideSuper ? 65 : 45);
            int borderAlpha = isBeingDragged ? 220 : (isInsideSuper ? 200 : 150);
            qreal borderW   = isBeingDragged ? 2.5 : (isInsideSuper ? 2.0 : 1.5);
            Qt::PenStyle borderStyle = (isBeingDragged || isInsideSuper) ? Qt::SolidLine : Qt::DashLine;
            QColor fill(cl.color.red(), cl.color.green(), cl.color.blue(), fillAlpha);
            QColor border(cl.color.red(), cl.color.green(), cl.color.blue(), borderAlpha);
            p.setBrush(fill);
            p.setPen(QPen(border, borderW, borderStyle));
            p.drawRoundedRect(cl.bounds, 14, 14);

            /* Cluster label in top-left of bounds */
            QString lbl = cl.label;
            qreal lx = cl.bounds.left() + 8;
            qreal ly = cl.bounds.top() + clfm.ascent() + 4;
            /* Black outline */
            QPainterPath tp;
            tp.addText(lx, ly, clf, lbl);
            p.setPen(QPen(QColor(0, 0, 0, 180), 3, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
            p.setBrush(Qt::NoBrush);
            p.drawPath(tp);
            /* Coloured fill */
            p.setPen(Qt::NoPen);
            p.setBrush(cl.color.lighter(160));
            p.drawPath(tp);
        }
    }

    /* ── Edges (behind nodes) ── */
    for (int i = 0; i < (int)m_edges.size(); i++) {
        const GraphEdge &e = m_edges[i];
        if (!e.pair) continue;

        if (!m_visiblePairs.isEmpty()) {
            bool vis = m_visiblePairs.contains(e.pair) ||
                       (e.reversePair && m_visiblePairs.contains(e.reversePair));
            if (!vis) continue;
        }
        if (!m_enabledProtocols.isEmpty() && e.pair->top_protocol) {
            if (!m_enabledProtocols.contains(QString::fromUtf8(e.pair->top_protocol))) continue;
        }

        bool hovered = (i == m_hoveredEdge);
        bool sel = false;
        for (comm_pair_t *sp : m_selectedPairs)
            if (sp == e.pair || sp == e.reversePair) { sel = true; break; }
        if (edgeFaded[i]) p.setOpacity(0.07);
        drawEdge(p, e, hovered, sel);
        if (edgeFaded[i]) p.setOpacity(1.0);
    }

    /* ── Outer hexagon rings (first pass, so inner rings draw on top) ── */
    for (int i = 0; i < (int)m_nodes.size(); i++) {
        const GraphNode &n = m_nodes[i];
        bool hl  = m_highlightedLabels.contains(n.rawAddr) ||
                   m_highlightedLabels.contains(n.displayLabel);
        bool sel = false;
        for (comm_pair_t *sp : m_selectedPairs)
            if (sp && ((sp->src_addr && n.rawAddr == QString::fromUtf8(sp->src_addr)) ||
                       (sp->dst_addr && n.rawAddr == QString::fromUtf8(sp->dst_addr))))
            { sel = true; break; }
        bool blinkOn = (hl || sel) && m_blinkState;
        if (nodeFaded[i]) p.setOpacity(0.12);
        drawHexNode(p, n, /*drawOuterOnly=*/true, hl || sel, blinkOn);
        if (nodeFaded[i]) p.setOpacity(1.0);
    }

    /* ── Inner hexagon rings + labels (second pass, in foreground) ── */
    for (int i = 0; i < (int)m_nodes.size(); i++) {
        const GraphNode &n = m_nodes[i];
        bool hl  = m_highlightedLabels.contains(n.rawAddr) ||
                   m_highlightedLabels.contains(n.displayLabel);
        bool sel = false;
        for (comm_pair_t *sp : m_selectedPairs)
            if (sp && ((sp->src_addr && n.rawAddr == QString::fromUtf8(sp->src_addr)) ||
                       (sp->dst_addr && n.rawAddr == QString::fromUtf8(sp->dst_addr))))
            { sel = true; break; }
        bool blinkOn = (hl || sel) && m_blinkState;
        if (nodeFaded[i]) p.setOpacity(0.12);
        drawHexNode(p, n, /*drawOuterOnly=*/false, hl || sel, blinkOn);
        if (nodeFaded[i]) p.setOpacity(1.0);
    }

    /* ── Restore screen-space transform for legend and zoom indicator ── */
    p.restore();

    /* ── Zoom level indicator (bottom-right) ── */
    if (qAbs(m_scale - 1.0) > 0.01) {
        QFont zf; zf.setPointSize(8); p.setFont(zf);
        QString zStr = QString("%1%").arg(qRound(m_scale * 100));
        QFontMetrics zfm(zf);
        int zw = zfm.horizontalAdvance(zStr) + 10;
        int zh = zfm.height() + 4;
        int zx = width()  - zw - 6;
        int zy = height() - zh - 6;
        p.fillRect(zx, zy, zw, zh, QColor(0, 0, 0, 140));
        p.setPen(QColor(200, 200, 200));
        p.drawText(zx + 5, zy + zfm.ascent() + 2, zStr);
    }

    /* ── Edge colour legend (bottom-right) ── */
    /* In WiFi mode always show RSSI legend; otherwise show for non-protocol modes */
    if (m_wifiMode || m_edgeColorMode != COLOR_PROTOCOL) {
        QFont lf; lf.setPointSize(8); p.setFont(lf);
        QFontMetrics fm(lf);

        struct LegItem { const char *label; QColor color; };

        LegItem items_health[]   = {
            { "Healthy",     healthColor(1.0)       },
            { "Moderate",    healthColor(0.6)        },
            { "Degraded",    healthColor(0.4)        },
            { "Unhealthy",   healthColor(0.0)        },
        };
        LegItem items_anomaly[]  = {
            { "Clean",       anomalyColor(0.0)       },
            { "Noteworthy",  anomalyColor(0.2)       },
            { "Suspicious",  anomalyColor(0.4)       },
            { "Anomalous",   anomalyColor(1.0)       },
        };
        /* Response-time legend labels derived from active threshold profile */
        const auto &RT = m_thresholds;
        QByteArray rt_b0 = QString("< %1 ms").arg(RT.rt_fast_ms).toUtf8();
        QByteArray rt_b1 = QString("%1\u2013%2 ms").arg(RT.rt_fast_ms).arg(RT.rt_moderate_ms).toUtf8();
        QByteArray rt_b2 = QString("%1\u2013%2 ms").arg(RT.rt_moderate_ms).arg(RT.rt_slow_ms).toUtf8();
        QByteArray rt_b3 = QString("%1\u2013%2 ms").arg(RT.rt_slow_ms).arg(RT.rt_very_slow_ms).toUtf8();
        QByteArray rt_b4 = QString("> %1 ms").arg(RT.rt_very_slow_ms).toUtf8();
        LegItem items_rt[]       = {
            { rt_b0.constData(), responseTimeColor(RT.rt_fast_ms      * 0.5,  RT) },
            { rt_b1.constData(), responseTimeColor(RT.rt_fast_ms      * 1.5,  RT) },
            { rt_b2.constData(), responseTimeColor(RT.rt_moderate_ms  * 1.5,  RT) },
            { rt_b3.constData(), responseTimeColor(RT.rt_slow_ms      * 1.5,  RT) },
            { rt_b4.constData(), responseTimeColor(RT.rt_very_slow_ms * 2.0,  RT) },
        };
        LegItem items_tp[]       = {
            { "< 10 KB/s",    throughputColor(1000.0)     },
            { "10-100 KB/s",  throughputColor(50000.0)    },
            { "100KB - 1MB/s",throughputColor(500000.0)   },
            { "1 - 10 MB/s",  throughputColor(5000000.0)  },
            { "> 10 MB/s",    throughputColor(50000000.0) },
        };

        LegItem items_wifi[] = {
            { "Excellent (>= -55 dBm)", rssiColor(nullptr) /* placeholder */ },
            { "Good      (-65..-56)",   rssiColor(nullptr) },
            { "Fair      (-75..-66)",   rssiColor(nullptr) },
            { "Poor      (< -75 dBm)",  rssiColor(nullptr) },
            { "No data",                QColor(160, 160, 160) },
        };
        /* Set actual RSSI colors via synthetic stubs */
        auto makeRssi = [](int dBm) -> comm_pair_t {
            comm_pair_t s; memset(&s, 0, sizeof(s));
            s.is_wifi = TRUE; s.rssi_count = 1;
            s.rssi_sum = (gint32)dBm;
            return s;
        };
        comm_pair_t rExc = makeRssi(-50); items_wifi[0].color = rssiColor(&rExc);
        comm_pair_t rGood= makeRssi(-60); items_wifi[1].color = rssiColor(&rGood);
        comm_pair_t rFair= makeRssi(-70); items_wifi[2].color = rssiColor(&rFair);
        comm_pair_t rPoor= makeRssi(-80); items_wifi[3].color = rssiColor(&rPoor);

        LegItem items_risk[] = {
            { "Critical (Telnet/VNC/FTP/X11)", m_darkTheme ? QColor(210, 35, 35) : QColor(185, 20, 20) },
            { "VPN / TOR",                     m_darkTheme ? QColor(160, 80,210) : QColor(120, 50,175) },
            { "High (RDP / WinRM)",            m_darkTheme ? QColor(235,110, 25) : QColor(205, 80, 10) },
            { "Elevated (SSH / SNMP)",         m_darkTheme ? QColor(220,185, 30) : QColor(185,150, 10) },
            { "Normal",                        m_darkTheme ? QColor(100,100,100) : QColor(140,140,140) },
        };
        LegItem items_window[] = {
            { "No stall  (>= 32 KB)",  windowPressureColor(32768, 0) },
            { "Mild      (8-32 KB)",   windowPressureColor( 8192, 0) },
            { "Moderate  (4-8 KB)",    windowPressureColor( 4096, 0) },
            { "Constrained (< 4 KB)",  windowPressureColor(    1, 0) },
            { "Zero-window stall",     windowPressureColor(    0, 1) },
        };

        const char *title = "";
        LegItem *items    = nullptr;
        int      nItems   = 0;
        if (m_wifiMode) {
            title="Signal Quality"; items=items_wifi; nItems=5;
        } else {
            switch (m_edgeColorMode) {
                case COLOR_TCP_HEALTH:    title="TCP Health";    items=items_health;  nItems=4; break;
                case COLOR_ANOMALY:       title="Anomaly";       items=items_anomaly; nItems=4; break;
                case COLOR_RESPONSE_TIME: title="Response Time"; items=items_rt;      nItems=5; break;
                case COLOR_THROUGHPUT:    title="Throughput";    items=items_tp;      nItems=5; break;
                case COLOR_HIGH_RISK:     title="High Risk";     items=items_risk;    nItems=5; break;
                case COLOR_TCP_WINDOW:    title="TCP Window";    items=items_window;  nItems=5; break;
                default: break;
            }
        }
        if (items && nItems > 0) {
            int lineH = 14;
            int legW  = 145;
            /* Compute hint metrics first so legH reserves the same gap as the node legend */
            QFont hf; hf.setPointSize(9);
            QFontMetrics fmHint(hf);
            int hintGap = fmHint.height() + 14; /* matches node legend bottom-padding */
            int legH  = nItems * lineH + 18 + hintGap;
            int lx    = width() - legW - 8;
            int ly    = height() - legH - 8;
            p.fillRect(lx - 4, ly - 2, legW + 8, legH + 4, QColor(0, 0, 0, 120));
            p.setPen(QColor(180, 180, 180));
            p.drawText(lx, ly + fm.ascent(), QString::fromUtf8(title));
            ly += 16;
            for (int i = 0; i < nItems; i++) {
                bool isActive = m_legendFilterColor.isValid() && !m_legendFilterIsNode
                                && (m_legendFilterColor == items[i].color);
                /* Record clickable rect */
                m_legendHitRects.append({QRect(lx - 2, ly, legW + 2, lineH),
                                         items[i].color, /*isNodeLeg=*/false});
                /* Selection highlight */
                if (isActive) {
                    p.setPen(QPen(Qt::white, 1.5));
                    p.setBrush(QColor(255,255,255,30));
                    p.drawRoundedRect(lx - 2, ly, legW + 2, lineH, 2, 2);
                }
                p.setPen(Qt::NoPen);
                p.setBrush(items[i].color);
                p.drawRect(lx, ly + 2, 10, 10);
                p.setPen(isActive ? Qt::white : QColor(200, 200, 200));
                p.setBrush(Qt::NoBrush);
                p.drawText(lx + 14, ly + fm.ascent(), QString::fromUtf8(items[i].label));
                ly += lineH;
            }
            /* "Click to filter" hint — 14 px gap below last item, matching node legend */
            p.setFont(hf);
            p.setPen(QColor(140, 140, 140));
            p.drawText(lx, ly + 14 + fmHint.ascent(), m_legendFilterColor.isValid() && !m_legendFilterIsNode
                       ? "click again to clear filter" : "Click Edge to filter");
        }
    }

    /* ── Node colour legend (bottom-left) ── */
    /* Layout order (bottom → top): hint baseline → items (drawn upward). */
    {
        int lx = 10;
        QFont lf; lf.setPointSize(8); p.setFont(lf);
        QFontMetrics fm(lf);
        QFont hf; hf.setPointSize(9);
        QFontMetrics fmHint(hf);

        /* Reserve space at bottom: hint + gap above it */
        int hint_y = height() - 8;                    /* hint text baseline    */
        int ly     = hint_y - fmHint.height() - 14;  /* items build upward    */

        auto drawLegItem = [&](const QString &label, QColor c, bool clickable, quint16 port = 0) {
            ly -= 16;
            bool isActive = clickable && m_legendFilterColor.isValid()
                            && m_legendFilterIsNode && (m_legendFilterColor == c);
            if (clickable)
                m_legendHitRects.append({QRect(lx, ly, 200, 16), c, /*isNodeLeg=*/true, port});
            if (isActive) {
                p.setPen(QPen(Qt::white, 1.5));
                p.setBrush(QColor(255,255,255,30));
                p.drawRoundedRect(lx, ly, 200, 16, 2, 2);
            }
            QColor fill(c.red(), c.green(), c.blue(), 180);
            p.setPen(QPen(c.lighter(150), 1.5));
            p.setBrush(fill);
            p.drawPolygon(makeHex(QPointF(lx + 7, ly + 7), 7));
            p.setPen(isActive ? Qt::white : QColor(220, 220, 220));
            p.setBrush(Qt::NoBrush);
            p.drawText(lx + 18, ly + fm.ascent(), label);
        };

        /* Draw items (each call decrements ly by 16, moving upward) */
        switch (m_nodeColorMode) {
            case NODECOLOR_SERVICE:
                for (const ServiceEntry &se : m_legendServices)
                    drawLegItem(QString("%1 (%2)").arg(se.name).arg(se.port), se.color, true, se.port);
                if (m_legendHasUnknown || m_legendServices.isEmpty())
                    drawLegItem("Other", portServiceColor(0), true, 0);
                break;
            case NODECOLOR_ROLE:
                drawLegItem("Internal",    m_darkTheme ? QColor( 70,130,180) : QColor( 41, 98,163), true);
                drawLegItem("External",    m_darkTheme ? QColor(220,100, 80) : QColor(180, 55, 35), true);
                drawLegItem("Broadcast",   m_darkTheme ? QColor(200,160, 64) : QColor(160,110, 10), true);
                drawLegItem("MAC/Unknown", m_darkTheme ? QColor(160,100,200) : QColor(110, 55,155), true);
                break;
            case NODECOLOR_FUNCTION:
                drawLegItem("Remote (RDP/VNC/Citrix)",    serviceCategoryColor(SC_REMOTE),       true);
                drawLegItem("Interactive (SSH/Telnet)",   serviceCategoryColor(SC_INTERACTIVE),  true);
                drawLegItem("Messaging (SIP/XMPP/IRC)",   serviceCategoryColor(SC_MESSAGING),    true);
                drawLegItem("Filetransfer (SMB/NFS/FTP)", serviceCategoryColor(SC_FILETRANSFER), true);
                drawLegItem("Other / uncategorised",
                    m_darkTheme ? QColor(100,100,100) : QColor(150,150,150), true);
                break;
            case NODECOLOR_PROTOCOL:
                drawLegItem("(protocol colours — same as circle view)", QColor(120,120,120), false);
                break;
        }

        /* Hint text */
        p.setFont(hf);
        p.setPen(QColor(140, 140, 140));
        p.drawText(lx, hint_y,
                   m_legendFilterColor.isValid() && m_legendFilterIsNode
                   ? "click again to clear filter" : "Click Protocol to select");
    }
}

void GraphWidget::toggleNodeEdges(int nodeIdx)
{
    if (nodeIdx < 0 || nodeIdx >= (int)m_nodes.size()) return;
    const QString &addr = m_nodes[nodeIdx].rawAddr;

    /* Collect both pair AND reversePair for every matching edge.
     * onNodeVisibilityToggle checks against the primary pair stored in each
     * pair-list row — which can be either direction — so we must include both
     * directions to guarantee a match regardless of which was stored as primary. */
    QSet<comm_pair_t*> seen;
    QList<comm_pair_t*> connected;
    for (const GraphEdge &e : m_edges) {
        if (!e.pair) continue;
        bool match = addr == QString::fromUtf8(e.pair->src_addr) ||
                     addr == QString::fromUtf8(e.pair->dst_addr);
        if (!match && e.reversePair)
            match = addr == QString::fromUtf8(e.reversePair->src_addr) ||
                    addr == QString::fromUtf8(e.reversePair->dst_addr);
        if (!match) continue;
        if (!seen.contains(e.pair))             { seen.insert(e.pair);         connected.append(e.pair); }
        if (e.reversePair && !seen.contains(e.reversePair)) {
            seen.insert(e.reversePair);
            connected.append(e.reversePair);
        }
    }
    if (connected.isEmpty()) return;
    bool allVisible = m_visiblePairs.isEmpty();
    if (!allVisible) {
        allVisible = true;
        for (comm_pair_t *p : connected) {
            if (!m_visiblePairs.contains(p)) { allVisible = false; break; }
        }
    }
    emit nodeVisibilityToggle(connected, !allVisible);
}

void GraphWidget::mousePressEvent(QMouseEvent *event)
{
    /* Middle button OR Space+left-button: start canvas pan */
    bool isSpaceLeft = (event->button() == Qt::LeftButton && m_spaceHeld);
    if (event->button() == Qt::MiddleButton || isSpaceLeft) {
        m_panning        = true;
        m_panStart       = event->position();
        m_panOffsetStart = m_panOffset;
        setCursor(Qt::ClosedHandCursor);
        return;
    }

    if (event->button() != Qt::LeftButton) return;

    /* ── Legend click-to-filter (screen-space, checked before world-space) ── */
    QPoint screenPt = event->position().toPoint();
    for (const LegItemHitRect &r : m_legendHitRects) {
        if (r.rect.contains(screenPt)) {
            if (m_legendFilterColor.isValid()
                && m_legendFilterIsNode == r.isNodeLeg
                && m_legendFilterColor  == r.color) {
                /* Same item clicked again → clear filter */
                m_legendFilterColor = QColor();
                m_legendFilterPort  = 0;
            } else {
                m_legendFilterColor  = r.color;
                m_legendFilterIsNode = r.isNodeLeg;
                m_legendFilterPort   = r.isNodeLeg ? r.port : 0;
            }

            /* Compute matching pairs and notify MainWindow so it can sync
             * the comm pair list checkboxes.                               */
            QList<comm_pair_t*> matchingPairs;
            if (m_legendFilterColor.isValid()) {
                /* Helper: check whether a pair has traffic on the filtered port */
                auto pairHasPort = [](comm_pair_t *p, quint16 port) -> bool {
                    if (!p || !p->dst_ports) return false;
                    return g_hash_table_lookup(p->dst_ports,
                               GUINT_TO_POINTER((guint)port)) != nullptr;
                };

                QSet<comm_pair_t*> seen;
                for (int i = 0; i < (int)m_edges.size(); i++) {
                    const GraphEdge &e = m_edges[i];
                    if (!e.pair) continue;
                    bool match = false;
                    if (m_legendFilterIsNode && m_legendFilterPort > 0) {
                        /* Service/port legend: match edges that carry that port */
                        match = pairHasPort(e.pair, m_legendFilterPort)
                             || pairHasPort(e.reversePair, m_legendFilterPort);
                    } else if (m_legendFilterIsNode) {
                        /* Role / Other legend: match by node colour (existing) */
                        bool sM = e.srcIdx >= 0 && e.srcIdx < (int)m_nodes.size()
                                  && m_nodes[e.srcIdx].color == m_legendFilterColor;
                        bool dM = e.dstIdx >= 0 && e.dstIdx < (int)m_nodes.size()
                                  && m_nodes[e.dstIdx].color == m_legendFilterColor;
                        match = sM || dM;
                    } else {
                        match = (e.color == m_legendFilterColor);
                    }
                    if (match) {
                        if (!seen.contains(e.pair)) {
                            seen.insert(e.pair);
                            matchingPairs.append(e.pair);
                        }
                        if (e.reversePair && !seen.contains(e.reversePair)) {
                            seen.insert(e.reversePair);
                            matchingPairs.append(e.reversePair);
                        }
                    }
                }
            }
            emit legendFilterChanged(matchingPairs, m_legendFilterColor.isValid());

            update();
            return;
        }
    }

    QPointF worldPos = screenToWorld(event->position());

    /* Node hit test comes first — a node inside a cluster takes priority over
     * the cluster blob so Ctrl+drag on a node always moves the node, not the
     * whole cluster. */
    int nodeIdx = hitTestNode(worldPos);
    if (nodeIdx >= 0) {
        if (event->modifiers() & Qt::ControlModifier) {
            /* Ctrl+drag → reposition node */
            m_draggedNode     = nodeIdx;
            m_dragging        = true;
            m_dragMoved       = false;
            m_dragPressScreen = event->position();
            m_dragOffset      = worldPos - m_nodes[nodeIdx].pos;
            setCursor(Qt::ClosedHandCursor);
        } else {
            /* Plain click → immediate reliable toggle (no drag ambiguity) */
            toggleNodeEdges(nodeIdx);
        }
        update();
        return;
    }

    /* ── Ctrl+click on a cluster blob (no node under cursor): move whole cluster ── */
    if ((event->modifiers() & Qt::ControlModifier) &&
        m_layoutMode == LAYOUT_CLUSTER && !m_clusters.isEmpty()) {
        for (int ci = 0; ci < (int)m_clusters.size(); ci++) {
            if (m_clusters[ci].bounds.contains(worldPos)) {
                m_draggedCluster  = ci;
                m_clusterDragLast = worldPos;
                setCursor(Qt::SizeAllCursor);
                update();
                return;
            }
        }
    }

    int edgeIdx = hitTestEdge(worldPos);
    if (edgeIdx >= 0 && m_edges[edgeIdx].pair) {
        emit lineClicked(m_edges[edgeIdx].pair, event->globalPosition().toPoint());
        update();
    }
}

void GraphWidget::mouseMoveEvent(QMouseEvent *event)
{
    QPointF screenPos = event->position();

    /* Middle-button pan */
    if (m_panning) {
        m_panOffset = m_panOffsetStart + (screenPos - m_panStart);
        update();
        return;
    }

    QPointF worldPos = screenToWorld(screenPos);

    /* ── Cluster drag ── */
    if (m_draggedCluster >= 0 && m_draggedCluster < (int)m_clusters.size()) {
        QPointF delta = worldPos - m_clusterDragLast;
        m_clusterDragLast = worldPos;
        Cluster &cl = m_clusters[m_draggedCluster];
        for (int ni : cl.nodeIndices)
            m_nodes[ni].pos += delta;
        cl.bounds.translate(delta);   /* keep bounds in sync without full recompute */
        update();
        return;
    }

    if (m_dragging && m_draggedNode >= 0) {
        QPointF np = worldPos - m_dragOffset;  /* world-space drag */
        qreal r = m_nodes[m_draggedNode].hexRadius;
        np.setX(qBound(r + 2, np.x(), (qreal)width()  - r - 2));
        np.setY(qBound(r + 2, np.y(), (qreal)height() - r - 2));
        m_nodes[m_draggedNode].pos = np;
        /* Only commit as a drag after moving > 4px from press (trackpad jitter guard) */
        if (QLineF(screenPos, m_dragPressScreen).length() > 4.0)
            m_dragMoved = true;
        update();
        return;
    }

    /* Legend items are screen-space — check before world-space hit testing */
    for (const LegItemHitRect &r : m_legendHitRects) {
        if (r.rect.contains(screenPos.toPoint())) {
            setCursor(Qt::PointingHandCursor);
            /* Clear any active edge hover so the pair-list highlight is removed */
            if (m_hoveredEdge >= 0) {
                m_hoveredEdge = -1;
                emit lineHovered(nullptr);
            }
            return;
        }
    }

    int prevN = m_hoveredNode, prevE = m_hoveredEdge;
    m_hoveredNode = hitTestNode(worldPos);
    m_hoveredEdge = (m_hoveredNode < 0) ? hitTestEdge(worldPos) : -1;

    /* Ctrl held over a cluster blob but NOT over a node → show move cursor */
    if ((event->modifiers() & Qt::ControlModifier) &&
        m_layoutMode == LAYOUT_CLUSTER && m_hoveredNode < 0) {
        for (const Cluster &cl : m_clusters) {
            if (cl.bounds.contains(worldPos)) {
                setCursor(Qt::SizeAllCursor);
                if (m_hoveredNode != prevN || m_hoveredEdge != prevE) update();
                return;
            }
        }
    }

    if (m_hoveredNode != prevN || m_hoveredEdge != prevE) {
        bool ctrlHeld = event->modifiers() & Qt::ControlModifier;
        setCursor(m_hoveredNode >= 0
                ? (ctrlHeld ? Qt::OpenHandCursor : Qt::PointingHandCursor)
                : m_hoveredEdge >= 0 ? Qt::PointingHandCursor
                : m_spaceHeld        ? Qt::OpenHandCursor
                : Qt::ArrowCursor);
        /* Emit lineHovered so the pair list can highlight the matching entry */
        if (m_hoveredEdge != prevE) {
            comm_pair_t *hpair = (m_hoveredEdge >= 0 && m_hoveredEdge < (int)m_edges.size())
                                 ? m_edges[m_hoveredEdge].pair : nullptr;
            emit lineHovered(hpair);
        }
        update();
    }

    /* Tooltip */
    if (m_hoveredNode >= 0) {
        const GraphNode &n = m_nodes[m_hoveredNode];
        QLocale loc;

        /* Scan pairs for per-direction stats and top destination ports */
        quint64 bytesSent = 0, bytesRecv = 0, pktsSent = 0, pktsRecv = 0;
        QHash<quint16, quint64> dstPortCounts;

        for (GList *it = m_pairs; it; it = it->next) {
            auto *pair = static_cast<comm_pair_t*>(it->data);
            if (!pair || !pair->src_addr || !pair->dst_addr) continue;
            bool isSrc = (n.rawAddr == QString::fromUtf8(pair->src_addr));
            bool isDst = (n.rawAddr == QString::fromUtf8(pair->dst_addr));
            if (!isSrc && !isDst) continue;
            if (isSrc) { bytesSent += pair->byte_count; pktsSent  += pair->packet_count; }
            else        { bytesRecv += pair->byte_count; pktsRecv  += pair->packet_count; }

            if (pair->dst_ports) {
                GHashTableIter piter;
                gpointer pkey, pval;
                g_hash_table_iter_init(&piter, pair->dst_ports);
                while (g_hash_table_iter_next(&piter, &pkey, &pval)) {
                    auto *ps = static_cast<port_stats_t*>(pval);
                    if (!ps) continue;
                    dstPortCounts[(quint16)(uintptr_t)pkey] += ps->count;
                }
            }
        }

        QString tip = QString("<b>%1</b>").arg(n.displayLabel.toHtmlEscaped());
        if (n.displayLabel != n.rawAddr)
            tip += QString("<br><small>%1</small>").arg(n.rawAddr.toHtmlEscaped());
        tip += QString("<br>Bytes sent: %1 &nbsp; Received: %2"
                       "<br>Packets sent: %3 &nbsp; Received: %4")
               .arg(loc.toString((qlonglong)bytesSent),
                    loc.toString((qlonglong)bytesRecv),
                    loc.toString((qlonglong)pktsSent),
                    loc.toString((qlonglong)pktsRecv));

        if (!dstPortCounts.isEmpty()) {
            QList<QPair<quint16,quint64>> portList;
            for (auto it = dstPortCounts.constBegin(); it != dstPortCounts.constEnd(); ++it)
                portList.append(qMakePair(it.key(), it.value()));
            std::sort(portList.begin(), portList.end(),
                [](const QPair<quint16,quint64> &a, const QPair<quint16,quint64> &b)
                { return a.second > b.second; });

            tip += "<br><b>Services (target ports):</b>";
            int shown = 0;
            for (const auto &entry : portList) {
                if (shown >= 8) {
                    tip += QString("<br>&nbsp;&nbsp;… +%1 more").arg(portList.size() - shown);
                    break;
                }
                QString svc = graphPortServiceName(entry.first);
                if (svc.isEmpty())
                    tip += QString("<br>&nbsp;&nbsp;Port %1 (%2 pkts)")
                           .arg(entry.first).arg(loc.toString((qlonglong)entry.second));
                else
                    tip += QString("<br>&nbsp;&nbsp;%1/%2 (%3 pkts)")
                           .arg(svc).arg(entry.first)
                           .arg(loc.toString((qlonglong)entry.second));
                shown++;
            }
        }

        QToolTip::showText(event->globalPosition().toPoint(), tip, this);
    } else if (m_hoveredEdge >= 0) {
        const GraphEdge &e = m_edges[m_hoveredEdge];
        if (e.pair) {
            quint64 totB    = e.pair->byte_count   + (e.reversePair ? e.reversePair->byte_count   : 0);
            quint64 totPkts = e.pair->packet_count + (e.reversePair ? e.reversePair->packet_count : 0);
            QString src  = e.pair->resolved_src ? QString::fromUtf8(e.pair->resolved_src) : QString::fromUtf8(e.pair->src_addr);
            QString dst  = e.pair->resolved_dst ? QString::fromUtf8(e.pair->resolved_dst) : QString::fromUtf8(e.pair->dst_addr);
            QString prot = e.pair->top_protocol  ? QString::fromUtf8(e.pair->top_protocol) : "?";
            QString dir  = e.bidirectional ? "&#8596;" : "&#8594; (one-way)";
            QLocale loc;
            QString tip = QString("<b>%1</b> %2 <b>%3</b><br>"
                                  "Protocol: %4 &nbsp; Bytes: %5 &nbsp; Packets: %6")
                .arg(src.toHtmlEscaped(), dir, dst.toHtmlEscaped(), prot.toHtmlEscaped())
                .arg(loc.toString((qlonglong)totB))
                .arg(loc.toString((qlonglong)totPkts));

            /* ── Mode-specific insight ── */
            if (m_wifiMode && e.pair->is_wifi) {
                if (e.pair->rssi_count > 0) {
                    int avg = (int)((qreal)e.pair->rssi_sum / (qreal)e.pair->rssi_count);
                    const char *label =
                        (avg >= -55) ? "Excellent" :
                        (avg >= -65) ? "Good" :
                        (avg >= -75) ? "Fair" : "Poor";
                    tip += QString("<br><b>Signal: %1</b> (avg %2 dBm, min %3, max %4)")
                           .arg(QLatin1String(label)).arg(avg)
                           .arg(e.pair->rssi_min).arg(e.pair->rssi_max);
                    if (e.pair->wifi_ssid)
                        tip += QString("<br>SSID: %1").arg(QString::fromUtf8(e.pair->wifi_ssid).toHtmlEscaped());
                    if (e.pair->wifi_channel > 0)
                        tip += QString(" &nbsp; Ch %1").arg(e.pair->wifi_channel);
                } else {
                    tip += "<br><b>Signal: N/A</b>";
                }
            } else if (m_edgeColorMode == COLOR_TCP_HEALTH) {
                const char *label =
                    (e.healthScore >= 0.75) ? "Healthy" :
                    (e.healthScore >= 0.50) ? "Moderate" :
                    (e.healthScore >= 0.28) ? "Degraded" : "Unhealthy";
                tip += QString("<br><b>TCP Health: %1</b> (%2%)")
                       .arg(QLatin1String(label)).arg(qRound(e.healthScore * 100));
                /* Surface key signals */
                qreal avg = totPkts > 0 ? (qreal)totB / totPkts : 0;
                int nP = e.pair->dst_ports ? (int)g_hash_table_size(e.pair->dst_ports) : 0;
                if (avg < 80)   tip += "<br><small>\u26a0 Very small avg packet size</small>";
                if (nP > 5)     tip += "<br><small>\u26a0 Many destination ports</small>";
                if (totPkts < 4)tip += "<br><small>\u26a0 Very few packets</small>";
                if (prot == QLatin1String("TCP"))
                                tip += "<br><small>\u26a0 No application protocol identified</small>";

            } else if (m_edgeColorMode == COLOR_ANOMALY) {
                const char *label =
                    (e.anomalyScore <= 0.12) ? "Clean" :
                    (e.anomalyScore <= 0.30) ? "Noteworthy" :
                    (e.anomalyScore <= 0.55) ? "Suspicious" : "Anomalous";
                tip += QString("<br><b>Anomaly: %1</b> (score %2%)")
                       .arg(QLatin1String(label)).arg(qRound(e.anomalyScore * 100));
                /* Surface detected signals */
                int nP = e.pair->dst_ports ? (int)g_hash_table_size(e.pair->dst_ports) : 0;
                qreal avg = totPkts > 0 ? (qreal)totB / totPkts : 0;
                if (nP > 5)  tip += QString("<br><small>\u26a0 %1 unique destination ports</small>").arg(nP);
                if (avg < 80 && totPkts > 15)
                             tip += "<br><small>\u26a0 High-volume tiny packets</small>";
                if (!e.bidirectional && totPkts > 100)
                             tip += "<br><small>\u26a0 One-way high-volume transfer</small>";
                if (e.pair->dst_ports) {
                    if (g_hash_table_contains(e.pair->dst_ports, GUINT_TO_POINTER(23u)))
                        tip += "<br><small>\u26a0 Telnet (port 23)</small>";
                    if (g_hash_table_contains(e.pair->dst_ports, GUINT_TO_POINTER(513u)) ||
                        g_hash_table_contains(e.pair->dst_ports, GUINT_TO_POINTER(514u)))
                        tip += "<br><small>\u26a0 Legacy rsh/rlogin</small>";
                }

            } else if (m_edgeColorMode == COLOR_RESPONSE_TIME) {
                if (e.responseTimeMs < 0) {
                    tip += "<br><b>Response Time: N/A</b><br><small>Requires bidirectional traffic with timestamps</small>";
                } else {
                    const char *label =
                        (e.responseTimeMs <   5) ? "Very Fast" :
                        (e.responseTimeMs <  50) ? "Fast" :
                        (e.responseTimeMs < 200) ? "Moderate" :
                        (e.responseTimeMs < 500) ? "Slow" : "Very Slow";
                    tip += QString("<br><b>Response Time: %1</b> (%2 ms)")
                           .arg(QLatin1String(label)).arg(loc.toString((double)e.responseTimeMs, 'f', 1));
                }

            } else if (m_edgeColorMode == COLOR_HIGH_RISK) {
                /* Enumerate the riskiest ports and explain them */
                struct { quint16 port; const char *label; int tier; } riskPorts[] = {
                    {23,    "Telnet (cleartext remote shell)",        4},
                    {21,    "FTP (cleartext credentials)",           4},
                    {20,    "FTP-Data",                              4},
                    {512,   "rexec (cleartext)",                     4},
                    {513,   "rlogin (cleartext)",                    4},
                    {514,   "rsh (cleartext)",                       4},
                    {69,    "TFTP (unauthenticated file transfer)",  4},
                    {5900,  "VNC (often no/weak auth)",              4},
                    {5901,  "VNC-1",                                 4},
                    {3389,  "RDP (Remote Desktop)",                  2},
                    {5985,  "WinRM (HTTP management)",               2},
                    {5986,  "WinRM (HTTPS management)",              2},
                    {7070,  "AnyDesk",                               2},
                    {1194,  "OpenVPN",                               3},
                    {51820, "WireGuard VPN",                         3},
                    {9050,  "TOR SOCKS proxy",                       3},
                    {9001,  "TOR relay",                             3},
                    {22,    "SSH",                                   1},
                    {1883,  "MQTT (unencrypted)",                    1},
                    {161,   "SNMP",                                  1},
                    {0,     nullptr,                                 0},
                };
                if (e.pair && e.pair->dst_ports) {
                    QStringList found;
                    for (int ri = 0; riskPorts[ri].label; ri++) {
                        if (g_hash_table_contains(e.pair->dst_ports,
                                GUINT_TO_POINTER((guint)riskPorts[ri].port)))
                            found << QString::fromUtf8(riskPorts[ri].label);
                    }
                    if (!found.isEmpty()) {
                        tip += "<br><b>Risk signals:</b><br><small>";
                        for (const QString &f : found)
                            tip += "\u26a0 " + f.toHtmlEscaped() + "<br>";
                        tip += "</small>";
                    } else {
                        tip += "<br><b>Risk: Normal</b> — no high-risk ports detected";
                    }
                    /* Note X11 range separately */
                    bool hasX11 = false;
                    GHashTableIter xi; gpointer xk, xv;
                    g_hash_table_iter_init(&xi, e.pair->dst_ports);
                    while (g_hash_table_iter_next(&xi, &xk, &xv)) {
                        quint16 xp = (quint16)(uintptr_t)xk;
                        if (xp >= 6000 && xp <= 6063) { hasX11 = true; break; }
                    }
                    if (hasX11)
                        tip += "<br><small>\u26a0 Native X11 (port 6000+) — unencrypted display protocol</small>";
                }

            } else if (m_edgeColorMode == COLOR_THROUGHPUT) {
                if (e.throughputBps <= 0) {
                    tip += "<br><b>Throughput: N/A</b><br><small>Duration too short to measure</small>";
                } else {
                    QString tpStr;
                    if      (e.throughputBps >= 1e9)  tpStr = QString("%1 GB/s").arg(e.throughputBps / 1e9, 0, 'f', 2);
                    else if (e.throughputBps >= 1e6)  tpStr = QString("%1 MB/s").arg(e.throughputBps / 1e6, 0, 'f', 2);
                    else if (e.throughputBps >= 1000)  tpStr = QString("%1 KB/s").arg(e.throughputBps / 1000, 0, 'f', 1);
                    else                               tpStr = QString("%1 B/s") .arg((int)e.throughputBps);
                    const char *label =
                        (e.throughputBps <     10000) ? "Minimal" :
                        (e.throughputBps <    100000) ? "Low" :
                        (e.throughputBps <   1000000) ? "Moderate" :
                        (e.throughputBps <  10000000) ? "High" : "Very High";
                    tip += QString("<br><b>Throughput: %1</b> (%2)")
                           .arg(QLatin1String(label)).arg(tpStr);
                }
            }

            tip += "<br><i>Click for details</i>";
            QToolTip::showText(event->globalPosition().toPoint(), tip, this);
        }
    } else {
        QToolTip::hideText();
    }
}

void GraphWidget::mouseReleaseEvent(QMouseEvent *event)
{
    if (m_panning &&
        (event->button() == Qt::MiddleButton || event->button() == Qt::LeftButton))
    {
        m_panning = false;
        setCursor(Qt::ArrowCursor);
        return;
    }
    if (m_draggedCluster >= 0) {
        m_draggedCluster = -1;
        setCursor(Qt::ArrowCursor);
        return;
    }

    if (m_dragging) {
        int clickedNode = m_draggedNode;
        bool wasDragged = m_dragMoved;
        m_dragging    = false;
        m_draggedNode = -1;
        m_dragMoved   = false;
        setCursor(m_hoveredNode >= 0 ? Qt::OpenHandCursor : Qt::ArrowCursor);

        /* Ctrl+click without drag → toggle (same as plain click) */
        if (!wasDragged && clickedNode >= 0 && clickedNode < (int)m_nodes.size())
            toggleNodeEdges(clickedNode);
    }
}

void GraphWidget::keyPressEvent(QKeyEvent *event)
{
    if (event->key() == Qt::Key_Control && !event->isAutoRepeat()) {
        if (m_hoveredNode >= 0 && !m_dragging)
            setCursor(Qt::OpenHandCursor);
        event->accept();
        return;
    }
    if (event->key() == Qt::Key_Space && !event->isAutoRepeat()) {
        m_spaceHeld = true;
        if (m_hoveredNode < 0 && m_hoveredEdge < 0)
            setCursor(Qt::OpenHandCursor);
        event->accept();
        return;
    }
    QWidget::keyPressEvent(event);
}

void GraphWidget::keyReleaseEvent(QKeyEvent *event)
{
    if (event->key() == Qt::Key_Control && !event->isAutoRepeat()) {
        if (m_hoveredNode >= 0 && !m_dragging)
            setCursor(Qt::PointingHandCursor);
        event->accept();
        return;
    }
    if (event->key() == Qt::Key_Space && !event->isAutoRepeat()) {
        m_spaceHeld = false;
        if (!m_panning) {
            bool ctrlHeld = event->modifiers() & Qt::ControlModifier;
            setCursor(m_hoveredNode >= 0
                    ? (ctrlHeld ? Qt::OpenHandCursor : Qt::PointingHandCursor)
                    : m_hoveredEdge >= 0 ? Qt::PointingHandCursor
                    : Qt::ArrowCursor);
        }
        event->accept();
        return;
    }
    QWidget::keyReleaseEvent(event);
}

void GraphWidget::focusOutEvent(QFocusEvent *event)
{
    /* Safety: if focus is lost while Space is held, reset state */
    if (m_spaceHeld) {
        m_spaceHeld = false;
        if (!m_panning)
            setCursor(Qt::ArrowCursor);
    }
    QWidget::focusOutEvent(event);
}

void GraphWidget::wheelEvent(QWheelEvent *event)
{
    qreal delta  = event->angleDelta().y();
    if (qAbs(delta) < 1.0) { event->ignore(); return; }

    qreal factor = (delta > 0) ? 1.15 : 1.0 / 1.15;
    qreal newScale = qBound(0.1, m_scale * factor, 10.0);
    if (qAbs(newScale - m_scale) < 1e-9) { event->accept(); return; }

    applyZoomAtPoint(m_scale, m_panOffset, newScale, event->position());
    event->accept();
    update();
}

void GraphWidget::resizeEvent(QResizeEvent *event)
{
    QWidget::resizeEvent(event);
    if (m_nodes.isEmpty()) return;
    QSize old = event->oldSize();
    if (!old.isValid() || old.width() <= 0) {
        relayout();
    } else {
        qreal sx = (qreal)event->size().width()  / old.width();
        qreal sy = (qreal)event->size().height() / old.height();
        for (GraphNode &n : m_nodes) { n.pos.setX(n.pos.x() * sx); n.pos.setY(n.pos.y() * sy); }
    }
    update();
}

/* ─────────────────────────────────────────────────────────────────────── *
 *  PDF legend accessor
 * ─────────────────────────────────────────────────────────────────────── */

QList<QPair<QString, QColor>> GraphWidget::legendServicesForPDF() const
{
    QList<QPair<QString, QColor>> result;
    for (const ServiceEntry &se : m_legendServices)
        result.append({se.name, se.color});
    if (m_legendHasUnknown)
        result.append({"Other/Unknown", QColor(120, 120, 120)});
    return result;
}

/* ─────────────────────────────────────────────────────────────────────── *
 *  PDF export
 * ─────────────────────────────────────────────────────────────────────── */

QPixmap GraphWidget::renderForPDF(int w, int h)
{
    QPixmap pixmap(w, h);
    pixmap.fill(Qt::white);
    if (m_nodes.isEmpty()) return pixmap;

    QList<QPointF> saved;
    saved.reserve(m_nodes.size());
    for (const GraphNode &n : m_nodes) saved.append(n.pos);

    qreal sx = (qreal)w / qMax(1, width());
    qreal sy = (qreal)h / qMax(1, height());
    for (GraphNode &n : m_nodes) { n.pos.setX(n.pos.x() * sx); n.pos.setY(n.pos.y() * sy); }

    QPainter p(&pixmap);
    p.setRenderHint(QPainter::Antialiasing);

    /* ── Cluster blobs (only in LAYOUT_CLUSTER, drawn behind everything) ── */
    if (m_layoutMode == LAYOUT_CLUSTER && !m_clusters.isEmpty()) {
        qreal baseR = m_nodes.isEmpty() ? 12.0 : m_nodes[0].hexRadius;
        /* Recompute bounds from the already-scaled node positions */
        QVector<QRectF> scaledBounds(m_clusters.size());
        for (int ci = 0; ci < (int)m_clusters.size(); ci++) {
            const Cluster &cl = m_clusters[ci];
            if (cl.nodeIndices.isEmpty()) continue;
            qreal xmin=1e9,xmax=-1e9,ymin=1e9,ymax=-1e9;
            for (int ni : cl.nodeIndices) {
                qreal x=m_nodes[ni].pos.x(), y=m_nodes[ni].pos.y();
                xmin=qMin(xmin,x); xmax=qMax(xmax,x);
                ymin=qMin(ymin,y); ymax=qMax(ymax,y);
            }
            qreal pad=baseR+24.0, topPad=pad+16.0;
            scaledBounds[ci] = QRectF(xmin-pad, ymin-topPad,
                                      (xmax-xmin)+2*pad, (ymax-ymin)+pad+topPad);
        }

        QFont clf; clf.setPointSize(9); clf.setBold(true);
        QFontMetrics clfm(clf);
        p.setFont(clf);

        for (int ci = 0; ci < (int)m_clusters.size(); ci++) {
            const Cluster &cl = m_clusters[ci];
            const QRectF &bnd = scaledBounds[ci];
            if (bnd.isNull() || cl.nodeIndices.isEmpty()) continue;

            QColor fill(cl.color.red(), cl.color.green(), cl.color.blue(), 35);
            QColor border(cl.color.red(), cl.color.green(), cl.color.blue(), 130);
            p.setBrush(fill);
            p.setPen(QPen(border, 1.5, Qt::DashLine));
            p.drawRoundedRect(bnd, 14, 14);

            /* Label top-left */
            qreal lx = bnd.left() + 8;
            qreal ly = bnd.top() + clfm.ascent() + 4;
            QPainterPath tp;
            tp.addText(lx, ly, clf, cl.label);
            p.setPen(QPen(QColor(0,0,0,180), 3, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
            p.setBrush(Qt::NoBrush);
            p.drawPath(tp);
            p.setPen(Qt::NoPen);
            p.setBrush(cl.color.lighter(160));
            p.drawPath(tp);
        }
    }

    for (const GraphEdge &e : m_edges) drawEdge(p, e, false, false);
    for (int i = 0; i < (int)m_nodes.size(); i++) drawHexNode(p, m_nodes[i], true,  false, false);
    for (int i = 0; i < (int)m_nodes.size(); i++) drawHexNode(p, m_nodes[i], false, false, false);

    for (int i = 0; i < (int)m_nodes.size(); i++) m_nodes[i].pos = saved[i];
    return pixmap;
}
