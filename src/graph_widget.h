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

#ifndef GRAPH_WIDGET_H
#define GRAPH_WIDGET_H

#include <QWidget>
#include <QColor>
#include <QPointF>
#include <QList>
#include <QHash>
#include <QSet>
#include <QPixmap>
#include <QTimer>
#include <QWheelEvent>
#include <QKeyEvent>
#include "packet_analyzer.h"

/**
 * GraphWidget — force-directed network topology visualization.
 *
 * Nodes use the same double-hexagon symbol as CircleWidget.
 * Node size scales with total traffic (log scale).
 *
 * Node color encoding (selectable):
 *   SERVICE   — dominant TCP/UDP service on this host (top port by packets)
 *   ROLE      — RFC-1918 / external / MAC / broadcast
 *   PROTOCOL  — dominant L7 protocol (same palette as circle view)
 *
 * Edge encoding:
 *   Thickness — bytes or packets (log scale, when Weight is on)
 *   Color     — protocol / TCP health / anomaly score (selectable)
 *   Opacity   — packet-count confidence
 *   Style     — solid = bidirectional, dashed = one-way
 *
 * Layout modes:
 *   FORCE     — Fruchterman-Reingold with centre gravity
 *   STAR      — busiest node at centre, others radially arranged
 *   CIRCULAR  — equal angular spacing (like circle view)
 *   GRID      — deterministic grid
 */
class GraphWidget : public QWidget
{
    Q_OBJECT

public:
    enum EdgeColorMode {
        COLOR_PROTOCOL      = 0, /**< Application protocol (same palette as circle view) */
        COLOR_TCP_HEALTH,        /**< Health: green=ok / yellow=moderate / orange=degraded / red=bad */
        COLOR_ANOMALY,           /**< Anomaly: green=clean / yellow=notable / orange=suspicious / red=alert */
        COLOR_RESPONSE_TIME,     /**< Initial response delay: green=<5ms … red=>500ms */
        COLOR_THROUGHPUT,        /**< Bytes/sec: blue=minimal … red=very high */
        COLOR_HIGH_RISK,         /**< Risk: grey=safe / yellow=elevated / orange=high / red=critical / purple=VPN/TOR */
        COLOR_TCP_WINDOW         /**< Window pressure: green=ok / yellow=mild / orange=constrained / red=zero-window stall */
    };

    enum NodeColorMode {
        NODECOLOR_SERVICE  = 0, /**< Dominant service/port on this host */
        NODECOLOR_ROLE,         /**< Network role: Internal / External / MAC / Broadcast */
        NODECOLOR_PROTOCOL,     /**< Dominant L7 protocol */
        NODECOLOR_FUNCTION      /**< Functional category: Remote / Interactive / Messaging / Filetransfer / Other */
    };

    /** Functional service category for a node — derived from destination ports it receives.
     *  Used in NODECOLOR_FUNCTION mode. Especially useful with cluster layout. */
    enum ServiceCategory {
        SC_NONE = 0,
        SC_REMOTE,       /**< Remote-desktop server: RDP, VNC, Citrix, AnyDesk, SPICE          */
        SC_INTERACTIVE,  /**< Interactive-shell server: SSH, Telnet, rsh/rexec/rlogin          */
        SC_MESSAGING,    /**< Messaging/comms: SIP, XMPP, IRC, STUN/WebRTC, MQTT              */
        SC_FILETRANSFER  /**< File-transfer server: SMB, NFS, FTP, TFTP, rsync                */
    };

    enum LayoutMode {
        LAYOUT_FORCE       = 0, /**< Fruchterman-Reingold force-directed              */
        LAYOUT_STAR,            /**< Busiest node at centre                           */
        LAYOUT_CIRCULAR,        /**< Equal angular spacing on a circle                */
        LAYOUT_GRID,            /**< Deterministic grid                               */
        LAYOUT_CLUSTER,         /**< Grouped by IP subnet with background blobs       */
        LAYOUT_CONCENTRIC,      /**< Concentric rings sorted by degree (most-conn inner) */
        LAYOUT_HIERARCHICAL,    /**< Tier-based: External → Gateway → Server → Client */
        LAYOUT_RADIAL           /**< BFS rings outward from most-connected node       */
    };

    /* ── Score breakdown (for ConnectionPopup Score button) ─────────── */
    struct ScoreFactor {
        QString description;  /**< Human-readable signal description */
        qreal   delta;        /**< Score contribution: +/− for health, +/+ for anomaly */
    };

    /* ── Configurable scoring thresholds ────────────────────────────── */
    struct GraphThresholds {
        QString name;                /**< Group name, e.g. "Default" */
        bool    builtIn = false;     /**< True for Default/Strict/Tolerant — cannot be deleted */

        /* TCP Health — packet size bins (bytes) */
        int hs_pkt_large;            /**< avg > this → +0.25  (default 800) */
        int hs_pkt_moderate;         /**< avg > this → +0.15  (default 300) */
        int hs_pkt_small;            /**< avg > this → +0.05  (default 100) */
        int hs_pkt_tiny;             /**< avg < this → -0.30  (default 80)  */
        /* TCP Health — packet count bins */
        int hs_pkt_very_few;         /**< count < this → -0.20 (default 4)  */
        int hs_pkt_few;              /**< count < this → -0.10 (default 10) */
        int hs_pkt_sustained;        /**< count > this → +0.10 (default 50) */
        /* TCP Health — port diversity bins */
        int hs_ports_high;           /**< ports > this → -0.25 (default 5)  */
        int hs_ports_elevated;       /**< ports > this → -0.10 (default 2)  */

        /* Response-time colour bins (ms) */
        int rt_fast_ms;              /**< green:        < this ms (default   5) */
        int rt_moderate_ms;          /**< yellow-green: < this ms (default  50) */
        int rt_slow_ms;              /**< yellow:       < this ms (default 200) */
        int rt_very_slow_ms;         /**< orange:       < this ms (default 500); red above */

        /* Anomaly — port diversity bins */
        int an_ports_critical;       /**< ports > this → +0.50 (default 20) */
        int an_ports_high;           /**< ports > this → +0.35 (default 10) */
        int an_ports_elevated;       /**< ports > this → +0.20 (default 5)  */
        int an_ports_slight;         /**< ports > this → +0.08 (default 2)  */
        /* Anomaly — scan detection */
        int  an_scan_min_ports;      /**< need > this ports before ppp check (default 3) */
        qreal an_scan_ppp;           /**< pkt/port < this → +0.20 (default 3.0) */
        /* Anomaly — flood detection */
        int an_flood_tiny_pkt;       /**< avg < this B → flood candidate (default 60) */
        int an_flood_tiny_count;     /**< combined with above: count > this → +0.25 (default 15) */
        int an_flood_small_pkt;      /**< avg < this B → mild flood (default 100) */
        int an_flood_small_count;    /**< combined: count > this → +0.10 (default 30) */
        /* Anomaly — one-way exfiltration */
        int an_oneway_count;         /**< one-way count > this → +0.15 (default 100) */

        static GraphThresholds defaults() {
            GraphThresholds t;
            t.name                = "Default";
            t.builtIn             = true;
            t.hs_pkt_large        = 800;
            t.hs_pkt_moderate     = 300;
            t.hs_pkt_small        = 100;
            t.hs_pkt_tiny         = 80;
            t.hs_pkt_very_few     = 4;
            t.hs_pkt_few          = 10;
            t.hs_pkt_sustained    = 50;
            t.hs_ports_high       = 5;
            t.hs_ports_elevated   = 2;
            t.rt_fast_ms          = 5;
            t.rt_moderate_ms      = 50;
            t.rt_slow_ms          = 200;
            t.rt_very_slow_ms     = 500;
            t.an_ports_critical   = 20;
            t.an_ports_high       = 10;
            t.an_ports_elevated   = 5;
            t.an_ports_slight     = 2;
            t.an_scan_min_ports   = 3;
            t.an_scan_ppp         = 3.0;
            t.an_flood_tiny_pkt   = 60;
            t.an_flood_tiny_count = 15;
            t.an_flood_small_pkt  = 100;
            t.an_flood_small_count= 30;
            t.an_oneway_count     = 100;
            return t;
        }

        /** Strict — tight thresholds; flags problems earlier */
        static GraphThresholds strict() {
            GraphThresholds t;
            t.name                = "Strict";
            t.builtIn             = true;
            t.hs_pkt_large        = 1200;
            t.hs_pkt_moderate     = 500;
            t.hs_pkt_small        = 200;
            t.hs_pkt_tiny         = 120;  /* wider "tiny" range → penalised more easily */
            t.hs_pkt_very_few     = 8;
            t.hs_pkt_few          = 20;
            t.hs_pkt_sustained    = 100;
            t.hs_ports_high       = 3;    /* fewer ports needed to flag */
            t.hs_ports_elevated   = 1;
            t.rt_fast_ms          = 2;    /* green only for sub-2 ms */
            t.rt_moderate_ms      = 20;
            t.rt_slow_ms          = 100;
            t.rt_very_slow_ms     = 300;
            t.an_ports_critical   = 10;
            t.an_ports_high       = 5;
            t.an_ports_elevated   = 3;
            t.an_ports_slight     = 1;
            t.an_scan_min_ports   = 2;
            t.an_scan_ppp         = 5.0;
            t.an_flood_tiny_pkt   = 80;
            t.an_flood_tiny_count = 10;
            t.an_flood_small_pkt  = 150;
            t.an_flood_small_count= 20;
            t.an_oneway_count     = 50;
            return t;
        }

        /** Tolerant — relaxed thresholds; only flags obvious problems */
        static GraphThresholds tolerant() {
            GraphThresholds t;
            t.name                = "Tolerant";
            t.builtIn             = true;
            t.hs_pkt_large        = 600;
            t.hs_pkt_moderate     = 200;
            t.hs_pkt_small        = 80;
            t.hs_pkt_tiny         = 50;   /* narrow "tiny" range → harder to penalise */
            t.hs_pkt_very_few     = 2;
            t.hs_pkt_few          = 5;
            t.hs_pkt_sustained    = 25;
            t.hs_ports_high       = 15;   /* many ports needed before flagging */
            t.hs_ports_elevated   = 5;
            t.rt_fast_ms          = 20;   /* green up to 20 ms */
            t.rt_moderate_ms      = 100;
            t.rt_slow_ms          = 500;
            t.rt_very_slow_ms     = 1500;
            t.an_ports_critical   = 50;
            t.an_ports_high       = 30;
            t.an_ports_elevated   = 15;
            t.an_ports_slight     = 5;
            t.an_scan_min_ports   = 5;
            t.an_scan_ppp         = 2.0;
            t.an_flood_tiny_pkt   = 40;
            t.an_flood_tiny_count = 30;
            t.an_flood_small_pkt  = 80;
            t.an_flood_small_count= 50;
            t.an_oneway_count     = 200;
            return t;
        }
    };

    /** User-configurable subnet entry: an IP range treated as "internal". */
    struct InternalSubnet {
        QString prefix;    /**< Network address, e.g. "10.0.0.0" or "192.168.0.0" */
        int     bits;      /**< Clustering prefix length (e.g. 24 = group by /24) */
        bool    builtIn;   /**< True = default RFC1918 range (cannot be removed in UI) */
    };
    static QList<InternalSubnet> defaultInternalSubnets();
    void setInternalSubnets(const QList<InternalSubnet> &subnets);
    const QList<InternalSubnet> &internalSubnets() const { return m_internalSubnets; }

    explicit GraphWidget(QWidget *parent = nullptr);
    ~GraphWidget() override;

    /* ── CircleWidget-compatible interface ─────────────────────────── */
    void setPairs(GList *pairs, GHashTable *protocols);
    void setMaxPairs(guint max_pairs);
    void setUseBytes(gboolean use_bytes);
    void setSelectedPairs(QList<comm_pair_t*> selected);
    void setVisiblePairs(QSet<comm_pair_t*> visible);
    void setShowLineThickness(gboolean show_thickness);
    void setProtocolFilter(QSet<QString> enabled_protocols);
    void setHighlightedLabels(const QSet<QString> &labels);
    void setDarkTheme(bool dark);
    void setWiFiMode(bool wifi);
    QPixmap renderForPDF(int w, int h);

    /* ── Graph-specific API ─────────────────────────────────────────── */
    void setEdgeColorMode(EdgeColorMode mode);
    void setNodeColorMode(NodeColorMode mode);
    void setLayoutMode(LayoutMode mode);
    void relayout();
    void lockPositions(bool locked);

    void setThresholds(const GraphThresholds &t) { m_thresholds = t; computeEdgeVisuals(); update(); }
    const GraphThresholds &thresholds() const { return m_thresholds; }

    /** Compute score breakdowns for \a pair (and optional \a reversePair).
     *  Fills \a healthFactors / \a anomalyFactors with the individual signals
     *  and writes the combined scores / metrics to the output pointers.
     *  Any output pointer may be nullptr to skip that output.
     *  responseTimeMsOut: first-packet round-trip delay in ms (−1 = unavailable).
     *  throughputBpsOut:  combined bytes/second (0 = unavailable). */
    void getScoreBreakdown(comm_pair_t *pair, comm_pair_t *reversePair,
                           QList<ScoreFactor> *healthFactors,
                           QList<ScoreFactor> *anomalyFactors,
                           qreal *healthScoreOut    = nullptr,
                           qreal *anomalyScoreOut   = nullptr,
                           qreal *responseTimeMsOut = nullptr,
                           qreal *throughputBpsOut  = nullptr) const;

    /** Return pre-computed TCP window stats for the edge that contains \a pair.
     *  Uses the same merged values shown as edge colour, so the score dialog
     *  and the edge colour always agree.  All output pointers are optional. */
    void getEdgeWindowStats(comm_pair_t *pair,
                            guint32 *winMinOut        = nullptr,
                            guint32 *winMaxOut        = nullptr,
                            gdouble *winAvgOut        = nullptr,
                            guint32 *zeroWinCountOut  = nullptr,
                            gdouble *zeroWinMaxDurMsOut = nullptr) const;

    EdgeColorMode edgeColorMode() const { return m_edgeColorMode; }
    NodeColorMode nodeColorMode() const { return m_nodeColorMode; }
    LayoutMode    layoutMode()    const { return m_layoutMode;    }

    /** PDF export: returns (name, colour) pairs for the service legend.
     *  Only populated when nodeColorMode() == NODECOLOR_SERVICE.
     *  Sorted by traffic volume (highest first). */
    QList<QPair<QString, QColor>> legendServicesForPDF() const;
    bool legendHasUnknown() const { return m_legendHasUnknown; }

signals:
    void pairClicked(comm_pair_t *pair);
    void pairSelectionChanged(QList<comm_pair_t*> selected);
    void nodeVisibilityToggle(QList<comm_pair_t*> pairs, bool enable);
    void lineClicked(comm_pair_t *pair, const QPoint &globalPos);
    void lineHovered(comm_pair_t *pair);  /**< nullptr when hover ends */
    /** Emitted when the legend click-to-filter state changes.
     *  \a matchingPairs: pairs that match the selected category (empty when filter cleared).
     *  \a active: true = filter applied, false = filter cleared. */
    void legendFilterChanged(QList<comm_pair_t*> matchingPairs, bool active);

public slots:
    void zoomIn();
    void zoomOut();
    void zoomReset();

protected:
    void paintEvent(QPaintEvent *event) override;
    void mousePressEvent(QMouseEvent *event) override;
    void mouseMoveEvent(QMouseEvent *event) override;
    void mouseReleaseEvent(QMouseEvent *event) override;
    void wheelEvent(QWheelEvent *event) override;
    void resizeEvent(QResizeEvent *event) override;
    void keyPressEvent(QKeyEvent *event) override;
    void keyReleaseEvent(QKeyEvent *event) override;
    void focusOutEvent(QFocusEvent *event) override;

private:
    /* ── Service legend entry (NODECOLOR_SERVICE mode) ──────────── */
    struct ServiceEntry {
        quint16 port;
        QString name;     /**< Known service name, e.g. "HTTPS" */
        QColor  color;
        quint64 packets;  /**< Total packets seen on this port across all pairs */
    };

    /** Outer bounding blob that wraps one or more sub-clusters.
     *  Currently used only in NODECOLOR_ROLE mode to group all internal subnet
     *  clusters under a single "Internal" umbrella blob. */
    struct SuperCluster {
        QString label;
        QColor  color;
        QRectF  bounds;
    };

    /* ── Cluster (used only in LAYOUT_CLUSTER mode) ─────────────── */
    struct Cluster {
        QString      label;       /**< Subnet label, e.g. "192.168.1.x" */
        QColor       color;       /**< Background fill / border colour   */
        QList<int>   nodeIndices; /**< Indices into m_nodes              */
        QRectF       bounds;      /**< Inflated bounding rect (in widget coords) */
    };

    /* ── Internal data structures ────────────────────────────────── */
    struct GraphNode {
        QString         rawAddr;
        QString         displayLabel;
        QPointF         pos;
        qreal           hexRadius;       /**< Outer hex radius in px (volume-scaled) */
        QColor          color;           /**< Driven by m_nodeColorMode */
        quint64         totalBytes;
        quint64         totalPackets;
        quint16         topPort;         /**< Port with most packets (0 = unknown) */
        ServiceCategory serviceCategory; /**< Functional role from inbound port profile */
    };

    struct GraphEdge {
        comm_pair_t *pair;
        comm_pair_t *reversePair;
        int          srcIdx;
        int          dstIdx;
        qreal        thickness;
        QColor       color;
        qreal        opacity;
        bool         bidirectional;
        qreal        healthScore;    /**< TCP health [0=unhealthy … 1=healthy], always computed */
        qreal        anomalyScore;   /**< Anomaly level [0=normal … 1=anomalous], always computed */
        qreal        responseTimeMs; /**< Initial response delay in ms (−1 = unavailable)        */
        qreal        throughputBps;  /**< Bytes/sec over connection lifetime (0 = unavailable)   */
        guint32      winMin;         /**< Min TCP receive window across both directions (G_MAXUINT32 = no data) */
        guint32      winMax;         /**< Max TCP receive window across both directions           */
        gdouble      winAvg;         /**< Average TCP receive window (0 = no data)               */
        guint32      zeroWinCount;   /**< Total zero-window events in either direction            */
        gdouble      zeroWinMaxDurMs;/**< Longest zero-window stall in ms                        */
    };

    /* ── Build / layout ─────────────────────────────────────────── */
    void buildGraph();
    void computeNodeColors();
    void computeEdgeVisuals();
    void applyLayout();

    /* Layout implementations */
    void layoutForce(int iterations = 150);
    void layoutStar();
    void layoutCircular();
    void layoutGrid();
    void layoutCluster();
    void layoutConcentric();
    void layoutHierarchical();
    void layoutRadial();

    /* WiFi cluster helpers */
    QString wifiClusterKey(int nodeIdx) const;
    static QColor wifiClusterColor(const QString &key);

    /* Legend / safe-area protection */
    void protectLegendArea();
    QString clusterKeyForAddr(const QString &addr) const;
    static QString subnetKeyFromParts(int a, int b, int c, int d, int bits);

    /* ── Visual helpers ─────────────────────────────────────────── */
    QColor serviceColor(quint16 port) const;
    QColor roleColor(const GraphNode &node) const;
    QColor serviceCategoryColor(ServiceCategory cat) const;
    QColor highRiskColor(comm_pair_t *pair) const;
    QColor protocolColor(const gchar *proto) const;
    bool   isRFC1918(const QString &ip) const;
    quint16 dominantPort(const QString &rawAddr) const;
    static ServiceCategory classifyServiceCategory(const QHash<quint16, quint64> &dstPorts);

    /* ── Drawing ────────────────────────────────────────────────── */
    void drawHexNode(QPainter &p, const GraphNode &node,
                     bool drawOuterOnly, bool highlighted, bool blinkOn) const;
    void drawEdge(QPainter &p, const GraphEdge &edge,
                  bool hovered, bool selected) const;
    static QPointF hexEdgeIntersect(const QPointF &from, const QPointF &to,
                                    const QPointF &center, qreal radius);
    static QPolygonF makeHex(const QPointF &center, qreal radius);

    /* ── Hit testing ────────────────────────────────────────────── */
    int hitTestNode(const QPointF &pt) const;
    int hitTestEdge(const QPointF &pt) const;

    /* ── Node interaction ───────────────────────────────────────── */
    void toggleNodeEdges(int nodeIdx);

    /* ── Coordinate conversion ───────────────────────────────────── */
    QPointF screenToWorld(const QPointF &screenPos) const;

    /* ── State ──────────────────────────────────────────────────── */
    GList      *m_pairs;
    GHashTable *m_protocols;
    QList<GraphNode>    m_nodes;
    QList<GraphEdge>    m_edges;
    QList<Cluster>      m_clusters;       /**< Populated only in LAYOUT_CLUSTER mode */
    QList<SuperCluster> m_superClusters;  /**< Populated only in LAYOUT_CLUSTER + NODECOLOR_ROLE mode */
    QList<InternalSubnet> m_internalSubnets;
    QList<ServiceEntry> m_legendServices; /**< All known services seen in current data, sorted by traffic */
    bool                m_legendHasUnknown; /**< TRUE if any traffic is on ports with no known service name */
    QHash<QString, int> m_addrToNode;
    QRectF m_legendRect;            /**< Bounding rect of the legend (set in applyLayout) */

    /* ── Legend click-to-filter ────────────────────────────────────── */
    /** One clickable row in the on-screen legend (screen-space coordinates). */
    struct LegItemHitRect {
        QRect   rect;
        QColor  color;      /**< The colour this item represents */
        bool    isNodeLeg;  /**< true = node-colour legend, false = edge-colour legend */
        quint16 port;       /**< Non-zero = service port (NODECOLOR_SERVICE items only) */
    };
    QList<LegItemHitRect> m_legendHitRects;  /**< Rebuilt every paintEvent */
    QColor  m_legendFilterColor;             /**< invalid = no filter active */
    bool    m_legendFilterIsNode;            /**< Which legend the filter belongs to */
    quint16 m_legendFilterPort;              /**< Non-zero = filter edges by port rather than node colour */

    QSet<comm_pair_t*>  m_visiblePairs;
    QList<comm_pair_t*> m_selectedPairs;
    QSet<QString>       m_enabledProtocols;
    QSet<QString>       m_highlightedLabels;

    EdgeColorMode m_edgeColorMode;
    NodeColorMode m_nodeColorMode;
    LayoutMode    m_layoutMode;

    gboolean m_useBytes;
    gboolean m_showThickness;
    bool     m_darkTheme;
    bool     m_wifiMode;
    bool     m_positionsLocked;
    guint    m_maxPairs;
    GraphThresholds m_thresholds;

    /* Interaction */
    int     m_hoveredNode;
    int     m_hoveredEdge;
    int     m_draggedNode;
    QPointF m_dragOffset;       /**< Offset from mouse to node centre, in world coords */
    bool    m_dragging;
    bool    m_dragMoved;        /**< True if the node actually moved during drag (distinguishes click from drag) */
    QPointF m_dragPressScreen;  /**< Screen position where the node press began (dead-zone reference) */
    int     m_draggedCluster;   /**< Index into m_clusters being dragged (-1 = none); Ctrl+drag on blob */
    QPointF m_clusterDragLast;  /**< Last world-space mouse position during cluster drag */

    /* Zoom / pan */
    qreal   m_scale;          /**< Current zoom level (1.0 = 100%) */
    QPointF m_panOffset;      /**< Screen-space translation applied before scale */
    bool    m_panning;        /**< Pan in progress (middle-button or Space+left) */
    bool    m_spaceHeld;      /**< Space bar is currently held down */
    QPointF m_panStart;       /**< Screen pos where pan started */
    QPointF m_panOffsetStart; /**< m_panOffset at the start of pan */

    /* Blink */
    QTimer *m_blinkTimer;
    bool    m_blinkState;
};

#endif /* GRAPH_WIDGET_H */
