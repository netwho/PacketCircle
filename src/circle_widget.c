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

#include "circle_widget.h"
#include "packet_analyzer.h"
#include <QtMath>
#include <QDebug>
#include <QSet>
#include <QStringList>
#include <QHash>
#include <QPainterPath>
#include <QToolTip>
#include <algorithm>

/* Map well-known TCP/UDP ports to service/application names */
static QString portToServiceName(quint16 port)
{
    switch (port) {
        case 20:   return "FTP-Data";
        case 21:   return "FTP";
        case 22:   return "SSH";
        case 23:   return "Telnet";
        case 25:   return "SMTP";
        case 53:   return "DNS";
        case 67:   return "DHCP";
        case 68:   return "DHCP";
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
        case 520:  return "RIP";
        case 587:  return "SMTP-Sub";
        case 636:  return "LDAPS";
        case 993:  return "IMAPS";
        case 995:  return "POP3S";
        case 1433: return "MSSQL";
        case 1434: return "MSSQL-Mon";
        case 1521: return "Oracle";
        case 2049: return "NFS";
        case 3306: return "MySQL";
        case 3389: return "RDP";
        case 5060: return "SIP";
        case 5061: return "SIPS";
        case 5432: return "PostgreSQL";
        case 5900: return "VNC";
        case 6379: return "Redis";
        case 8080: return "HTTP-Proxy";
        case 8443: return "HTTPS-Alt";
        case 9200: return "Elasticsearch";
        case 27017: return "MongoDB";
        default:   return QString();
    }
}

CircleWidget::CircleWidget(QWidget *parent)
    : QWidget(parent)
    , m_pairs(NULL)
    , m_protocols(NULL)
    , m_max_pairs(10)
    , m_use_bytes(FALSE)
    , m_show_line_thickness(FALSE)
    , m_radius(150.0)
    , m_node_radius(10.0)  /* Slightly larger nodes for better visibility */
    , m_blinkTimer(nullptr)
    , m_blinkState(false)
    , m_pdfMode(false)
    , m_darkTheme(true)
    , m_wifiMode(false)
    , m_wifiThresholds(CircleWidget::WifiThresholds::defaults())
    , m_hoveredLinePair(nullptr)
{
    setMinimumSize(300, 300);
    setMouseTracking(true);
    
    /* Create timer for blinking selected lines - initially stopped */
    m_blinkTimer = new QTimer(this);
    connect(m_blinkTimer, &QTimer::timeout, this, &CircleWidget::onBlinkTimer);
    /* Timer will be started when pairs are selected */
}

CircleWidget::~CircleWidget()
{
    qDeleteAll(m_nodes);
    m_nodes.clear();
}

void CircleWidget::setPairs(GList *pairs, GHashTable *protocols)
{
    /* Clear old nodes before setting new pairs */
    qDeleteAll(m_nodes);
    m_nodes.clear();
    m_last_hovered_label.clear();
    m_nodeStats.clear();
    m_nodePairs.clear();
    
    m_pairs = pairs;
    m_protocols = protocols;
    
    if (pairs) {
        calculateLayout();
        rebuildNodeCaches();
    }
    update();
}

void CircleWidget::setMaxPairs(guint max_pairs)
{
    m_max_pairs = max_pairs;
    calculateLayout();
    update();
}

void CircleWidget::setUseBytes(gboolean use_bytes)
{
    m_use_bytes = use_bytes;
    update();
}

void CircleWidget::onBlinkTimer()
{
    m_blinkState = !m_blinkState;
    if (!m_selected_pairs.isEmpty() || !m_highlighted_labels.isEmpty()) {
        update();  /* Redraw to show/hide blinking line */
    }
}

void CircleWidget::setShowLineThickness(gboolean show_thickness)
{
    m_show_line_thickness = show_thickness;
    update();
}

void CircleWidget::setProtocolFilter(QSet<QString> enabled_protocols)
{
    m_enabled_protocols = enabled_protocols;
    update();
}

void CircleWidget::setDarkTheme(bool dark)
{
    m_darkTheme = dark;
    update();
}

void CircleWidget::setWiFiMode(bool wifi)
{
    m_wifiMode = wifi;
    update();
}

void CircleWidget::setHighlightedLabels(const QSet<QString> &labels)
{
    m_highlighted_labels = labels;
    updateBlinkTimer();
    update();
}

void CircleWidget::setVisiblePairs(QSet<comm_pair_t*> visible)
{
    m_visible_pairs = visible;
    update();  /* Redraw with new visibility */
}

void CircleWidget::setSelectedPairs(QList<comm_pair_t*> selected)
{
    bool had_selections = !m_selected_pairs.isEmpty();
    m_selected_pairs = selected;
    updateSelection();
    updateBlinkTimer();
    
    /* Force update if selection state changed */
    if (had_selections != !m_selected_pairs.isEmpty()) {
        update();
    }
}

void CircleWidget::calculateLayout()
{
    qDeleteAll(m_nodes);
    m_nodes.clear();

    if (!m_pairs)
        return;

    /* Use the pairs that were already passed to setPairs() */
    /* They are already filtered to top N pairs by the caller */
    
    /* Create unique node list from pairs - use resolved names for display */
    QSet<QString> unique_addresses;
    QHash<QString, QString> addr_to_display;  /* raw address -> display name */
    GList *iter;
    
    for (iter = m_pairs; iter; iter = iter->next) {
        comm_pair_t *pair = (comm_pair_t *)iter->data;
        if (!pair || !pair->src_addr || !pair->dst_addr)
            continue;
        QString srcRaw = QString::fromUtf8(pair->src_addr);
        QString dstRaw = QString::fromUtf8(pair->dst_addr);
        QString srcDisplay = pair->resolved_src ? QString::fromUtf8(pair->resolved_src) : srcRaw;
        QString dstDisplay = pair->resolved_dst ? QString::fromUtf8(pair->resolved_dst) : dstRaw;
        if (!unique_addresses.contains(srcRaw)) {
            unique_addresses.insert(srcRaw);
            addr_to_display[srcRaw] = srcDisplay;
        }
        if (!unique_addresses.contains(dstRaw)) {
            unique_addresses.insert(dstRaw);
            addr_to_display[dstRaw] = dstDisplay;
        }
    }

    /* Create nodes */
    guint index = 0;
    QStringList address_list = unique_addresses.values();
    guint total_nodes = static_cast<guint>(address_list.size());

    if (total_nodes == 0) {
        qDebug() << "CircleWidget::calculateLayout: No unique addresses found";
        return;
    }

    m_center = QPointF(width() / 2.0, height() / 2.0);
    
    /* Determine dominant protocol color for each node */
    QHash<QString, QColor> node_colors;
    for (const QString &addr : address_list) {
        QHash<QString, guint> protocol_counts;
        /* Count protocols for this address */
        for (iter = m_pairs; iter; iter = iter->next) {
            comm_pair_t *pair = (comm_pair_t *)iter->data;
            if (!pair || !pair->top_protocol)
                continue;
            if (pair->src_addr == addr || pair->dst_addr == addr) {
                QString proto = QString::fromUtf8(pair->top_protocol);
                protocol_counts[proto]++;
            }
        }
        /* Find most common protocol */
        QString dominant_proto;
        guint max_count = 0;
        for (auto it = protocol_counts.begin(); it != protocol_counts.end(); ++it) {
            if (it.value() > max_count) {
                max_count = it.value();
                dominant_proto = it.key();
            }
        }
        /* Get color for dominant protocol */
        node_colors[addr] = getProtocolColor(dominant_proto.toUtf8().constData());
    }
    int dim = qMin(width(), height());
    m_radius = dim / 2.0 - 50.0;
    /* Scale node radius proportionally: range ~6px (small) to ~14px (large) */
    m_node_radius = qMax(6.0, dim / 80.0);

    for (const QString &addr : address_list) {
        NodePosition *node = new NodePosition;
        node->label = addr;
        node->displayLabel = addr_to_display.value(addr, addr);  /* Resolved name or raw */
        node->position = getNodePosition(index++, total_nodes);
        node->is_selected = false;
        node->pair = NULL; /* Will be set per connection */
        node->protocol_color = node_colors.value(addr, QColor(128, 128, 128));  /* Default gray if no protocol found */
        m_nodes.append(node);
    }

    qDebug() << "CircleWidget::calculateLayout: Created" << m_nodes.size() << "nodes from" << g_list_length(m_pairs) << "pairs";
}

QPointF CircleWidget::getNodePosition(guint index, guint total)
{
    if (total == 0)
        return m_center;

    qreal angle = (2.0 * M_PI * index) / total;
    qreal x = m_center.x() + m_radius * qCos(angle);
    qreal y = m_center.y() + m_radius * qSin(angle);
    return QPointF(x, y);
}

QPointF CircleWidget::getLineHexagonIntersection(const QPointF &lineStart, const QPointF &lineEnd, 
                                                  const QPointF &hexCenter, qreal hexRadius)
{
    /* Calculate direction vector */
    QPointF dir = lineEnd - lineStart;
    qreal dirLength = qSqrt(dir.x() * dir.x() + dir.y() * dir.y());
    if (dirLength == 0)
        return hexCenter;
    
    QPointF unitDir(dir.x() / dirLength, dir.y() / dirLength);
    
    /* Calculate vector from hex center to line start */
    QPointF toStart = lineStart - hexCenter;
    
    /* Solve quadratic equation: |hexCenter + t*unitDir - lineStart|^2 = hexRadius^2 */
    /* Simplified: |toStart + t*unitDir|^2 = hexRadius^2 */
    /* t^2 + 2*(toStart·unitDir)*t + |toStart|^2 - hexRadius^2 = 0 */
    qreal a = 1.0;  /* unitDir·unitDir = 1 */
    qreal b = 2.0 * (toStart.x() * unitDir.x() + toStart.y() * unitDir.y());
    qreal c = toStart.x() * toStart.x() + toStart.y() * toStart.y() - hexRadius * hexRadius;
    
    qreal discriminant = b * b - 4 * a * c;
    if (discriminant < 0)
        return hexCenter;  /* No intersection, return center as fallback */
    
    qreal t = (-b + qSqrt(discriminant)) / (2 * a);
    if (t < 0)
        t = (-b - qSqrt(discriminant)) / (2 * a);
    
    /* Return intersection point */
    return lineStart + unitDir * t;
}

void CircleWidget::drawConnection(QPainter &painter, const NodePosition &src,
                                  const NodePosition &dst, comm_pair_t *pair, guint64 max_volume, bool is_emphasized, bool isOneway)
{
    if (!pair || max_volume == 0)
        return;

    /* Calculate line thickness based on volume (if enabled) */
    qreal thickness;
    if (is_emphasized && m_show_line_thickness) {
        guint64 volume = getPairVolume(pair);
        thickness = 1.0 + (10.0 * volume / max_volume);
        thickness = qBound(1.0, thickness, 10.0);
    } else {
        /* Fixed thickness when disabled or deemphasized */
        thickness = is_emphasized ? 2.0 : 1.0;
    }

    /* Get connection color — RSSI-based for Wi-Fi, protocol-based otherwise */
    QColor color;
    if (m_wifiMode && pair->is_wifi) {
        color = getRssiColor(pair);
    } else {
        color = getProtocolColor(pair->top_protocol);
        if (m_pdfMode) {
            color = color.darker(150);
        }
    }
    if (!is_emphasized) {
        color.setAlpha(80);
    }
    
    /* Highlight selected pairs with dotted red blinking line */
    if (m_selected_pairs.contains(pair)) {
        /* Use red color for selected pairs - blink on/off */
        if (m_blinkState) {
            color = QColor(255, 0, 0);  /* Red when visible */
        } else {
            color = QColor(255, 0, 0, 50);  /* Semi-transparent red when blinking off */
        }
        thickness = 3.0;  /* Slightly thicker for visibility */
        
        /* Create dotted pen for blinking effect */
        QPen pen(color, thickness);
        pen.setStyle(Qt::DashLine);
        pen.setDashPattern(QVector<qreal>() << 5 << 5);  /* 5px dash, 5px gap */
        pen.setCapStyle(Qt::RoundCap);
        painter.setPen(pen);
    } else if (pair->has_tcp && pair->has_udp) {
        /* Mixed TCP+UDP pair - check if protocol filter narrows to one */
        bool tcp_enabled = m_enabled_protocols.isEmpty() || m_enabled_protocols.contains("TCP");
        bool udp_enabled = m_enabled_protocols.isEmpty() || m_enabled_protocols.contains("UDP");

        if (tcp_enabled && udp_enabled) {
            /* Both protocols visible: draw alternating dotted line */
            QColor tcp_color = getProtocolColor("TCP");
            QColor udp_color = getProtocolColor("UDP");
            if (m_pdfMode) {
                tcp_color = tcp_color.darker(150);
                udp_color = udp_color.darker(150);
            }
            if (!is_emphasized) {
                tcp_color.setAlpha(80);
                udp_color.setAlpha(80);
            }
            QPen tcp_pen(tcp_color, thickness);
            tcp_pen.setStyle(Qt::DashLine);
            tcp_pen.setDashPattern(QVector<qreal>() << 6 << 6);
            tcp_pen.setDashOffset(0);
            tcp_pen.setCapStyle(Qt::RoundCap);

            QPen udp_pen(udp_color, thickness);
            udp_pen.setStyle(Qt::DashLine);
            udp_pen.setDashPattern(QVector<qreal>() << 6 << 6);
            udp_pen.setDashOffset(6);
            udp_pen.setCapStyle(Qt::RoundCap);

            /* Calculate intersection points with hexagon boundaries */
            QPointF srcIntersect = getLineHexagonIntersection(src.position, dst.position, src.position, m_node_radius);
            QPointF dstIntersect = getLineHexagonIntersection(dst.position, src.position, dst.position, m_node_radius);

            painter.setPen(tcp_pen);
            painter.drawLine(srcIntersect, dstIntersect);
            painter.setPen(udp_pen);
            painter.drawLine(srcIntersect, dstIntersect);
            return;
        } else {
            /* Only one protocol selected: show solid line with that protocol's color */
            const char *active_protocol = tcp_enabled ? "TCP" : "UDP";
            color = getProtocolColor(active_protocol);
            if (m_pdfMode) {
                color = color.darker(150);
            }
            if (!is_emphasized) {
                color.setAlpha(80);
            }
            QPen pen(color, thickness);
            pen.setCapStyle(Qt::RoundCap);
            painter.setPen(pen);
        }
    } else if (isOneway) {
        /* One-way connection: short-dash pattern to indicate single direction */
        QPen pen(color, thickness);
        pen.setStyle(Qt::DashLine);
        pen.setDashPattern(QVector<qreal>() << 4 << 4);
        pen.setCapStyle(Qt::RoundCap);
        painter.setPen(pen);
    } else {
        QPen pen(color, thickness);
        pen.setCapStyle(Qt::RoundCap);
        painter.setPen(pen);
    }

    /* Calculate intersection points with hexagon boundaries */
    QPointF srcIntersect = getLineHexagonIntersection(src.position, dst.position, src.position, m_node_radius);
    QPointF dstIntersect = getLineHexagonIntersection(dst.position, src.position, dst.position, m_node_radius);

    /* Draw line from intersection point to intersection point */
    painter.drawLine(srcIntersect, dstIntersect);
}

void CircleWidget::drawNode(QPainter &painter, NodePosition *node, QColor node_color, bool drawInnerOnly)
{
    if (!node)
        return;
    
    /* Use node color (matches connection line color) */
    QColor outline_color = node_color;
    bool is_highlighted = m_highlighted_labels.contains(node->label);
    bool blink_on = (is_highlighted && m_blinkState);
    if (blink_on) {
        outline_color = QColor(255, 0, 0);
    }
    qreal radius = m_node_radius;
    
    if (!drawInnerOnly) {
        /* Draw outer hexagon shape with transparent fill and colored outline */
        QPolygonF hexagon;
        for (int i = 0; i < 6; i++) {
            qreal angle = (M_PI / 3.0) * i;  /* 60 degrees per vertex */
            qreal x = node->position.x() + radius * qCos(angle);
            qreal y = node->position.y() + radius * qSin(angle);
            hexagon << QPointF(x, y);
        }
        
        /* Draw hexagon with transparent fill and colored outline */
        painter.setPen(QPen(outline_color, blink_on ? 3.5 : 2.5));  /* Thicker outline when highlighted */
        painter.setBrush(Qt::NoBrush);  /* Transparent fill */
        painter.drawPolygon(hexagon);
    }
    
    /* Draw inner smaller hexagon for depth (always drawn, appears in foreground) */
    QPolygonF inner_hexagon;
    qreal inner_radius = radius * 0.6;
    for (int i = 0; i < 6; i++) {
        qreal angle = (M_PI / 3.0) * i;
        qreal x = node->position.x() + inner_radius * qCos(angle);
        qreal y = node->position.y() + inner_radius * qSin(angle);
        inner_hexagon << QPointF(x, y);
    }
    /* Draw inner hexagon with semi-transparent fill so it appears in foreground */
    painter.setPen(QPen(outline_color.lighter(150), blink_on ? 2.8 : 2.0));
    QColor fill_color(outline_color.red(), outline_color.green(), outline_color.blue(), blink_on ? 220 : 180);
    painter.setBrush(QBrush(fill_color));  /* Semi-transparent fill */
    painter.drawPolygon(inner_hexagon);

    /* Draw label - scale font based on widget dimensions */
    QFont font = painter.font();
    int fontSize;
    if (m_pdfMode) {
        fontSize = 18;
    } else {
        int dim = qMin(width(), height());
        if (dim < 400)       fontSize = 7;
        else if (dim < 600)  fontSize = 8;
        else if (dim < 800)  fontSize = 9;
        else if (dim < 1000) fontSize = 10;
        else                 fontSize = 11;
    }
    font.setPointSize(fontSize);
    font.setBold(true);
    painter.setFont(font);
    
    /* Use displayLabel (resolved name) for rendering, fall back to raw label */
    QString displayText = node->displayLabel.isEmpty() ? node->label : node->displayLabel;
    QPainterPath textPath;
    QFontMetrics fm(font);
    qreal text_x = node->position.x() - fm.horizontalAdvance(displayText) / 2.0;
    qreal text_y = node->position.y() + m_node_radius + 18;
    textPath.addText(text_x, text_y, font, displayText);
    
    if (m_pdfMode) {
        /* PDF mode: black text on white background */
        painter.setPen(Qt::NoPen);
        painter.setBrush(QBrush(QColor(0, 0, 0)));
        painter.drawPath(textPath);
    } else {
        /* On-screen: white text with black outline (always black background) */
        painter.setPen(QPen(QColor(0, 0, 0), 4, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
        painter.drawPath(textPath);
        painter.setPen(Qt::NoPen);
        painter.setBrush(QBrush(QColor(255, 255, 255)));
        painter.drawPath(textPath);
    }
}

QColor CircleWidget::getProtocolColor(const gchar *protocol_name)
{
    QString proto_str;
    if (!protocol_name || !*protocol_name) {
        qDebug() << "CircleWidget::getProtocolColor: NULL or empty protocol name, using gray";
        proto_str = "Unknown";
    } else {
        proto_str = QString::fromUtf8(protocol_name);
        /* Check for Qt's "Missing Protocol Name" placeholder */
        if (proto_str.contains("Missing", Qt::CaseInsensitive)) {
            qDebug() << "CircleWidget::getProtocolColor: Detected 'Missing' in protocol name, using Unknown";
            proto_str = "Unknown";
        }
    }

    guint32 rgb = packet_analyzer_get_protocol_color(proto_str.toUtf8().constData());
    QColor color((rgb >> 16) & 0xFF, (rgb >> 8) & 0xFF, rgb & 0xFF);
    qDebug() << "CircleWidget::getProtocolColor: protocol=" << proto_str << "color=" << QString::number(rgb, 16);
    return color;
}

/* Map average RSSI (dBm) to a color using 4 bins driven by m_wifiThresholds:
 *   Excellent: >= rssi_excellent  →  green
 *   Good:      >= rssi_good       →  yellow-green
 *   Fair:      >= rssi_fair       →  orange
 *   Poor:      below rssi_fair    →  red
 * Returns a neutral grey when no RSSI data is available.
 * Thresholds are configurable via Settings → WiFi Thresholds. */
QColor CircleWidget::getRssiColor(comm_pair_t *pair)
{
    if (!pair || !pair->is_wifi || pair->rssi_count == 0)
        return QColor(160, 160, 160);  /* Neutral grey — no RSSI data */

    int avg = (int)(pair->rssi_sum / (gint32)pair->rssi_count);

    if (avg >= m_wifiThresholds.rssi_excellent)
        return m_pdfMode ? QColor(0, 160, 0) : QColor(0, 200, 0);      /* Excellent — green */
    if (avg >= m_wifiThresholds.rssi_good)
        return m_pdfMode ? QColor(120, 180, 0) : QColor(160, 220, 0);  /* Good — yellow-green */
    if (avg >= m_wifiThresholds.rssi_fair)
        return m_pdfMode ? QColor(200, 140, 0) : QColor(255, 165, 0);  /* Fair — orange */
    return m_pdfMode ? QColor(180, 0, 0) : QColor(220, 30, 30);        /* Poor — red */
}

void CircleWidget::setWifiThresholds(const WifiThresholds &t)
{
    m_wifiThresholds = t;
    update();
}

guint64 CircleWidget::getPairVolume(comm_pair_t *pair)
{
    if (!pair)
        return 0;
    return m_use_bytes ? pair->byte_count : pair->packet_count;
}

void CircleWidget::paintEvent(QPaintEvent *event)
{
    Q_UNUSED(event);

    QPainter painter(this);
    painter.setRenderHint(QPainter::Antialiasing);

    /* Clear background — always black for on-screen, white for PDF */
    QColor bgColor = m_pdfMode ? QColor(255, 255, 255) : QColor(0, 0, 0);
    painter.fillRect(rect(), bgColor);

    if (!m_pairs || m_nodes.size() == 0) {
        qDebug() << "CircleWidget::paintEvent: No pairs or nodes (pairs=" << (void*)m_pairs << ", nodes=" << m_nodes.size() << ")";
        return;
    }
    
    qDebug() << "CircleWidget::paintEvent: Drawing" << g_list_length(m_pairs) << "pairs with" << m_nodes.size() << "nodes";

    /* Find maximum volume for scaling */
    guint64 max_volume = 0;
    GList *iter;
    for (iter = m_pairs; iter; iter = iter->next) {
        comm_pair_t *pair = (comm_pair_t *)iter->data;
        if (!pair) {
            qDebug() << "CircleWidget::paintEvent: Found NULL pair in list";
            continue;
        }
        guint64 volume = getPairVolume(pair);
        if (volume > max_volume)
            max_volume = volume;
    }

    if (max_volume == 0)
        return;

    /* Track which nodes have been drawn to avoid duplicates */
    QSet<QString> drawn_nodes;

    /* Build set of visible (src→dst) keys so we can detect one-way connections */
    QSet<QString> visibleDirKeys;
    for (GList *it2 = m_pairs; it2; it2 = it2->next) {
        comm_pair_t *p2 = (comm_pair_t *)it2->data;
        if (!p2 || !m_visible_pairs.contains(p2)) continue;
        visibleDirKeys.insert(QString::fromUtf8(p2->src_addr) + QChar('\x01') +
                              QString::fromUtf8(p2->dst_addr));
    }

    /* Draw connections and nodes together - nodes colored to match connection */
    for (iter = m_pairs; iter; iter = iter->next) {
        comm_pair_t *pair = (comm_pair_t *)iter->data;
        if (!pair || !pair->src_addr || !pair->dst_addr) {
            qDebug() << "CircleWidget::paintEvent: Skipping invalid pair";
            continue;
        }
        
        /* Filter by visibility - only show pairs in the visible set */
        /* Skip pairs that are not checked in the pair list */
        if (!m_visible_pairs.contains(pair)) {
            continue;  /* Skip pairs not in the visible set */
        }
        bool is_emphasized = true;
        
        /* Filter by protocol if filter is set */
        if (!m_enabled_protocols.isEmpty()) {
            bool protocol_match = false;
            /* Check top_protocol */
            if (pair->top_protocol) {
                QString protocol = QString::fromUtf8(pair->top_protocol);
                if (m_enabled_protocols.contains(protocol))
                    protocol_match = true;
            }
            /* Also check has_tcp/has_udp for mixed pairs */
            if (pair->has_tcp && m_enabled_protocols.contains("TCP"))
                protocol_match = true;
            if (pair->has_udp && m_enabled_protocols.contains("UDP"))
                protocol_match = true;
            if (!protocol_match)
                continue;  /* Skip this pair - no matching protocol enabled */
        }
        
        NodePosition *src_node = NULL;
        NodePosition *dst_node = NULL;

        /* Find nodes for this pair */
        for (NodePosition *node : m_nodes) {
            if (node->label == pair->src_addr)
                src_node = node;
            if (node->label == pair->dst_addr)
                dst_node = node;
        }

        if (src_node && dst_node) {
            /* One-way if no reverse pair is visible */
            QString revKey = QString::fromUtf8(pair->dst_addr) + QChar('\x01') +
                             QString::fromUtf8(pair->src_addr);
            bool isOneway = !visibleDirKeys.contains(revKey);
            /* Draw connection */
            drawConnection(painter, *src_node, *dst_node, pair, max_volume, is_emphasized, isOneway);
            
            /* Get color for this connection — RSSI for Wi-Fi, protocol otherwise */
            QColor connection_color = (m_wifiMode && pair->is_wifi)
                ? getRssiColor(pair)
                : getProtocolColor(pair->top_protocol);
            
            /* Draw source node outer hexagon if not already drawn */
            if (!drawn_nodes.contains(src_node->label)) {
                drawNode(painter, src_node, connection_color, false);
                drawn_nodes.insert(src_node->label);
            }
            
            /* Draw destination node outer hexagon if not already drawn */
            if (!drawn_nodes.contains(dst_node->label)) {
                drawNode(painter, dst_node, connection_color, false);
                drawn_nodes.insert(dst_node->label);
            }
        }
    }
    
    /* Draw inner hexagons after all lines (so they appear in foreground) */
    for (NodePosition *node : m_nodes) {
        if (drawn_nodes.contains(node->label)) {
            /* Find the color for this node from its connections */
            QColor node_color = node->protocol_color;
            for (iter = m_pairs; iter; iter = iter->next) {
                comm_pair_t *pair = (comm_pair_t *)iter->data;
                if (!pair || !pair->src_addr || !pair->dst_addr)
                    continue;
                if (pair->src_addr == node->label || pair->dst_addr == node->label) {
                    node_color = getProtocolColor(pair->top_protocol);
                    break;  /* Use first connection's color */
                }
            }
            drawNode(painter, node, node_color, true);  /* Draw inner hexagon only */
        }
    }
    
    /* Draw any remaining nodes that weren't part of connections (shouldn't happen, but safety) */
    for (NodePosition *node : m_nodes) {
        if (!drawn_nodes.contains(node->label)) {
            QColor node_color = node->is_selected ? QColor(255, 200, 0) : node->protocol_color;
            drawNode(painter, node, node_color, false);
        }
    }
}

void CircleWidget::mousePressEvent(QMouseEvent *event)
{
    if (event->button() != Qt::LeftButton)
        return;

    NodePosition *node = findNodeAt(event->pos());
    if (node) {
        QList<comm_pair_t*> connected_pairs = m_nodePairs.value(node->label);

        if (!connected_pairs.isEmpty()) {
            bool all_visible = !m_visible_pairs.isEmpty();
            if (all_visible) {
                for (comm_pair_t *pair : connected_pairs) {
                    if (!m_visible_pairs.contains(pair)) {
                        all_visible = false;
                        break;
                    }
                }
            }
            emit nodeVisibilityToggle(connected_pairs, !all_visible);
        }

        update();
        showTooltipForNode(node, event->globalPosition().toPoint());
        return;
    }

    /* No node clicked - check for line click */
    comm_pair_t *line_pair = findLineAt(event->pos());
    if (line_pair) {
        emit lineClicked(line_pair, event->globalPosition().toPoint());
    }
}

void CircleWidget::mouseMoveEvent(QMouseEvent *event)
{
    NodePosition *node = findNodeAt(event->pos());
    if (node) {
        if (node->label != m_last_hovered_label) {
            showTooltipForNode(node, event->globalPosition().toPoint());
            m_last_hovered_label = node->label;
        }
        /* Left a line when entering a node */
        if (m_hoveredLinePair) {
            m_hoveredLinePair = nullptr;
            emit lineHovered(nullptr);
        }
    } else {
        if (!m_last_hovered_label.isEmpty()) {
            QToolTip::hideText();
            m_last_hovered_label.clear();
        }
        /* Check if hovering over a connection line */
        comm_pair_t *linePair = findLineAt(event->pos());
        if (linePair != m_hoveredLinePair) {
            m_hoveredLinePair = linePair;
            emit lineHovered(linePair);
        }
    }
}

void CircleWidget::resizeEvent(QResizeEvent *event)
{
    Q_UNUSED(event);
    calculateLayout();
}

CircleWidget::NodePosition* CircleWidget::findNodeAt(const QPointF &point)
{
    for (NodePosition *node : m_nodes) {
        qreal distance = qSqrt(qPow(point.x() - node->position.x(), 2) + 
                              qPow(point.y() - node->position.y(), 2));
        if (distance <= m_node_radius) {
            return node;
        }
    }
    return NULL;
}

comm_pair_t* CircleWidget::findLineAt(const QPointF &point)
{
    if (!m_pairs)
        return NULL;

    comm_pair_t *best_pair = NULL;
    qreal best_dist = 1e9;

    for (GList *iter = m_pairs; iter; iter = iter->next) {
        comm_pair_t *pair = (comm_pair_t *)iter->data;
        if (!pair || !pair->src_addr || !pair->dst_addr)
            continue;

        /* Must be visible */
        if (!m_visible_pairs.contains(pair))
            continue;

        /* Find the two node positions */
        QPointF srcPos, dstPos;
        bool found_src = false, found_dst = false;
        for (NodePosition *node : m_nodes) {
            if (node->label == pair->src_addr) { srcPos = node->position; found_src = true; }
            if (node->label == pair->dst_addr) { dstPos = node->position; found_dst = true; }
            if (found_src && found_dst) break;
        }
        if (!found_src || !found_dst)
            continue;

        /* Calculate distance from point to line segment (srcPos -> dstPos) */
        QPointF d = dstPos - srcPos;
        qreal len2 = d.x() * d.x() + d.y() * d.y();
        if (len2 < 1.0)
            continue;  /* Degenerate line */

        /* Project point onto line, clamped to [0, 1] */
        QPointF p = point - srcPos;
        qreal t = qBound(0.0, (p.x() * d.x() + p.y() * d.y()) / len2, 1.0);
        QPointF closest = srcPos + t * d;
        QPointF diff = point - closest;
        qreal dist = qSqrt(diff.x() * diff.x() + diff.y() * diff.y());

        /* Determine line thickness for hit test */
        guint64 volume = getPairVolume(pair);
        guint64 max_volume = 1;
        for (GList *mi = m_pairs; mi; mi = mi->next) {
            comm_pair_t *mp = (comm_pair_t *)mi->data;
            if (mp) {
                guint64 v = getPairVolume(mp);
                if (v > max_volume) max_volume = v;
            }
        }
        qreal lineThickness = m_show_line_thickness ? 
            qBound(1.0, 1.0 + (10.0 * volume / max_volume), 10.0) : 2.0;
        qreal threshold = qMax(4.0, lineThickness + 3.0);

        if (dist < threshold && dist < best_dist) {
            best_dist = dist;
            best_pair = pair;
        }
    }

    return best_pair;
}

void CircleWidget::updateSelection()
{
    /* Update selected pairs based on selected nodes */
    m_selected_pairs.clear();
    
    GList *iter;
    for (iter = m_pairs; iter; iter = iter->next) {
        comm_pair_t *pair = (comm_pair_t *)iter->data;
        bool src_selected = false;
        bool dst_selected = false;

        for (NodePosition *node : m_nodes) {
            if (node->is_selected) {
                if (node->label == pair->src_addr)
                    src_selected = true;
                if (node->label == pair->dst_addr)
                    dst_selected = true;
            }
        }

        if (src_selected || dst_selected) {
            m_selected_pairs.append(pair);
        }
    }

    emit pairSelectionChanged(m_selected_pairs);
}

QString CircleWidget::buildTooltipText(NodePosition *node) const
{
    if (!node) {
        return QString();
    }

    if (!m_nodeStats.contains(node->label)) {
        return QString(
            "Mac Address: N/A\n"
            "IP Address: N/A\n"
            "Bytes received: 0\n"
            "Bytes sent: 0\n"
            "Packets received: 0\n"
            "Packets sent: 0"
        );
    }

    const NodeStats &stats = m_nodeStats[node->label];

    QString tooltip = QString(
        "Mac Address: %1\n"
        "IP Address: %2\n"
        "Bytes received: %3\n"
        "Bytes sent: %4\n"
        "Packets received: %5\n"
        "Packets sent: %6"
    ).arg(stats.mac_address.isEmpty() ? QString("N/A") : stats.mac_address)
     .arg(stats.ip_address.isEmpty() ? QString("N/A") : stats.ip_address)
     .arg(QString::number(static_cast<qulonglong>(stats.bytes_received)))
     .arg(QString::number(static_cast<qulonglong>(stats.bytes_sent)))
     .arg(QString::number(static_cast<qulonglong>(stats.packets_received)))
     .arg(QString::number(static_cast<qulonglong>(stats.packets_sent)));

    /* Add Wi-Fi info if applicable */
    if (m_wifiMode) {
        /* Gather Wi-Fi-specific data from connected pairs */
        for (GList *iter = m_pairs; iter; iter = iter->next) {
            comm_pair_t *pair = (comm_pair_t *)iter->data;
            if (!pair || !pair->is_wifi) continue;
            if (node->label != QString::fromUtf8(pair->src_addr) &&
                node->label != QString::fromUtf8(pair->dst_addr))
                continue;
            if (pair->wifi_ssid) {
                tooltip += QString("\nSSID: %1").arg(QString::fromUtf8(pair->wifi_ssid));
            }
            if (pair->wifi_bssid) {
                tooltip += QString("\nBSSID: %1").arg(QString::fromUtf8(pair->wifi_bssid));
            }
            if (pair->wifi_channel > 0) {
                tooltip += QString("\nChannel: %1").arg(pair->wifi_channel);
            }
            if (pair->rssi_count > 0) {
                int avg = (int)(pair->rssi_sum / (gint32)pair->rssi_count);
                tooltip += QString("\nRSSI: avg %1 dBm (min %2, max %3)")
                    .arg(avg).arg(pair->rssi_min).arg(pair->rssi_max);
            }
            if (pair->retry_count > 0) {
                tooltip += QString("\nRetries: %1").arg(pair->retry_count);
            }
            break;  /* Show first matching pair's Wi-Fi info */
        }
    }

    /* Add destination port / service information */
    if (!stats.dst_ports.isEmpty()) {
        /* Sort ports by packet count (descending) */
        QList<QPair<quint16, quint64>> port_list;
        for (auto it = stats.dst_ports.constBegin(); it != stats.dst_ports.constEnd(); ++it) {
            port_list.append(qMakePair(it.key(), it.value()));
        }
        std::sort(port_list.begin(), port_list.end(),
                  [](const QPair<quint16, quint64> &a, const QPair<quint16, quint64> &b) {
                      return a.second > b.second;
                  });

        tooltip += "\n\nServices (target ports):";
        int shown = 0;
        for (const auto &entry : port_list) {
            if (shown >= 10) {
                int remaining = (int)port_list.size() - shown;
                tooltip += QString("\n  ... +%1 more").arg(remaining);
                break;
            }
            quint16 port = entry.first;
            quint64 count = entry.second;
            QString service = portToServiceName(port);
            if (service.isEmpty()) {
                tooltip += QString("\n  Port %1 (%2 pkts)").arg(port).arg(count);
            } else {
                tooltip += QString("\n  %1/%2 (%3 pkts)").arg(service).arg(port).arg(count);
            }
            shown++;
        }
    }

    return tooltip;
}

void CircleWidget::showTooltipForNode(NodePosition *node, const QPoint &global_pos)
{
    QString tooltip = buildTooltipText(node);
    if (!tooltip.isEmpty()) {
        QToolTip::showText(global_pos, tooltip, this);
    }
}

void CircleWidget::rebuildNodeCaches()
{
    m_nodeStats.clear();
    m_nodePairs.clear();

    for (GList *iter = m_pairs; iter; iter = iter->next) {
        comm_pair_t *pair = (comm_pair_t *)iter->data;
        if (!pair || !pair->src_addr || !pair->dst_addr)
            continue;

        QString src_label = QString::fromUtf8(pair->src_addr);
        QString dst_label = QString::fromUtf8(pair->dst_addr);

        NodeStats &src_stats = m_nodeStats[src_label];
        src_stats.bytes_sent += pair->byte_count;
        src_stats.packets_sent += pair->packet_count;
        src_stats.label_is_mac = pair->is_mac;
        if (src_stats.mac_address.isEmpty() && pair->src_mac)
            src_stats.mac_address = QString::fromUtf8(pair->src_mac);
        if (src_stats.ip_address.isEmpty() && pair->src_ip)
            src_stats.ip_address = QString::fromUtf8(pair->src_ip);

        NodeStats &dst_stats = m_nodeStats[dst_label];
        dst_stats.bytes_received += pair->byte_count;
        dst_stats.packets_received += pair->packet_count;
        dst_stats.label_is_mac = pair->is_mac;
        if (dst_stats.mac_address.isEmpty() && pair->dst_mac)
            dst_stats.mac_address = QString::fromUtf8(pair->dst_mac);
        if (dst_stats.ip_address.isEmpty() && pair->dst_ip)
            dst_stats.ip_address = QString::fromUtf8(pair->dst_ip);

        if (pair->is_mac) {
            if (src_stats.mac_address.isEmpty())
                src_stats.mac_address = src_label;
            if (dst_stats.mac_address.isEmpty())
                dst_stats.mac_address = dst_label;
        } else {
            if (src_stats.ip_address.isEmpty())
                src_stats.ip_address = src_label;
            if (dst_stats.ip_address.isEmpty())
                dst_stats.ip_address = dst_label;
        }

        /* Aggregate destination ports for the destination node */
        if (pair->dst_ports) {
            GHashTableIter port_iter;
            gpointer port_key, port_value;
            g_hash_table_iter_init(&port_iter, pair->dst_ports);
            while (g_hash_table_iter_next(&port_iter, &port_key, &port_value)) {
                quint16 port = (quint16)GPOINTER_TO_UINT(port_key);
                port_stats_t *ps = (port_stats_t *)port_value;
                if (port > 0 && ps) {
                    dst_stats.dst_ports[port] += ps->count;
                }
            }
        }

        m_nodePairs[src_label].append(pair);
        m_nodePairs[dst_label].append(pair);
    }
}

void CircleWidget::updateBlinkTimer()
{
    bool needs_blink = !m_selected_pairs.isEmpty() || !m_highlighted_labels.isEmpty();
    if (needs_blink) {
        if (!m_blinkTimer->isActive()) {
            m_blinkTimer->start(500);  /* Blink every 500ms */
            m_blinkState = true;  /* Start visible */
        }
    } else if (m_blinkTimer->isActive()) {
        m_blinkTimer->stop();
        m_blinkState = false;  /* Reset blink state */
    }
}

QPixmap CircleWidget::renderForPDF(int width, int height)
{
    /* Save current geometry */
    QSize origSize = size();
    qreal origRadius = m_radius;
    qreal origNodeRadius = m_node_radius;

    /* Temporarily resize to the requested size for high-res rendering */
    resize(width, height);
    calculateLayout();

    /* Enable PDF mode */
    m_pdfMode = true;

    /* Render into a pixmap */
    QPixmap pixmap(width, height);
    pixmap.fill(Qt::white);
    QPainter painter(&pixmap);
    painter.setRenderHint(QPainter::Antialiasing);
    paintEvent(nullptr);  /* This paints to the widget; we need to paint to our pixmap */
    painter.end();

    /* Actually, paintEvent paints onto the widget, not onto our pixmap.
     * Use render() instead which redirects painting to a paint device. */
    pixmap.fill(Qt::white);
    render(&pixmap);

    /* Restore everything */
    m_pdfMode = false;
    resize(origSize);
    m_radius = origRadius;
    m_node_radius = origNodeRadius;
    calculateLayout();

    return pixmap;
}
