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

#ifndef CIRCLE_WIDGET_H
#define CIRCLE_WIDGET_H

#include <QWidget>
#include <QPainter>
#include <QMouseEvent>
#include <QList>
#include <QSet>
#include <QString>
#include <QTimer>
#include <QFontMetrics>
#include <glib.h>

/* Include packet_analyzer.h for full comm_pair_t definition (required by Qt MOC on Linux) */
#include "packet_analyzer.h"

class CircleWidget : public QWidget
{
    Q_OBJECT

public:
    explicit CircleWidget(QWidget *parent = nullptr);
    ~CircleWidget();

    void setPairs(GList *pairs, GHashTable *protocols);
    void setMaxPairs(guint max_pairs);
    void setUseBytes(gboolean use_bytes);
    void setSelectedPairs(QList<comm_pair_t*> selected);
    void setVisiblePairs(QSet<comm_pair_t*> visible);
    void setShowLineThickness(gboolean show_thickness);
    void setProtocolFilter(QSet<QString> enabled_protocols);
    void setHighlightedLabels(const QSet<QString> &labels);
    QPixmap renderForPDF(int width, int height);

signals:
    void pairClicked(comm_pair_t *pair);
    void pairSelectionChanged(QList<comm_pair_t*> selected);
    void nodeVisibilityToggle(QList<comm_pair_t*> pairs, bool enable);

private slots:
    void onBlinkTimer();

protected:
    void paintEvent(QPaintEvent *event) override;
    void mousePressEvent(QMouseEvent *event) override;
    void mouseMoveEvent(QMouseEvent *event) override;
    void resizeEvent(QResizeEvent *event) override;

private:
    struct NodePosition {
        comm_pair_t *pair;
        QPointF position;
        QString label;
        gboolean is_selected;
        QColor protocol_color;  /* Color based on dominant protocol */
    };
    struct NodeStats {
        guint64 bytes_sent = 0;
        guint64 bytes_received = 0;
        guint64 packets_sent = 0;
        guint64 packets_received = 0;
        bool label_is_mac = false;
        QString mac_address;
        QString ip_address;
        QMap<quint16, quint64> dst_ports;  /* Ports targeted on this node (as destination) */
    };

    void calculateLayout();
    QPointF getNodePosition(guint index, guint total);
    QPointF getLineHexagonIntersection(const QPointF &lineStart, const QPointF &lineEnd, const QPointF &hexCenter, qreal hexRadius);
    void drawConnection(QPainter &painter, const NodePosition &src, const NodePosition &dst, 
                       comm_pair_t *pair, guint64 max_volume, bool is_emphasized);
    void drawNode(QPainter &painter, NodePosition *node, QColor node_color, bool drawInnerOnly = false);
    QColor getProtocolColor(const gchar *protocol_name);
    guint64 getPairVolume(comm_pair_t *pair);
    struct NodePosition* findNodeAt(const QPointF &point);
    void updateSelection();
    QString buildTooltipText(NodePosition *node) const;
    void showTooltipForNode(NodePosition *node, const QPoint &global_pos);
    void rebuildNodeCaches();
    void updateBlinkTimer();

    GList *m_pairs;
    GHashTable *m_protocols;
    QList<NodePosition*> m_nodes;
    QHash<QString, NodeStats> m_nodeStats;
    QHash<QString, QList<comm_pair_t*>> m_nodePairs;
    QList<comm_pair_t*> m_selected_pairs;  /* Pairs selected for blinking highlight */
    QSet<comm_pair_t*> m_visible_pairs;  /* Pairs that should be visible (empty = hide all) */
    QSet<QString> m_enabled_protocols;  /* Protocols to show (empty = show all) */
    QSet<QString> m_highlighted_labels;
    guint m_max_pairs;
    gboolean m_use_bytes;
    gboolean m_show_line_thickness;
    QPointF m_center;
    qreal m_radius;
    qreal m_node_radius;
    QTimer *m_blinkTimer;
    bool m_blinkState;
    bool m_pdfMode;
    QString m_last_hovered_label;
};

#endif /* CIRCLE_WIDGET_H */
