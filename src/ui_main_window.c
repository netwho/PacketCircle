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

#include "ui_main_window.h"
#include "ui_bridge.h"
#include "packet_analyzer.h"
#include <memory>
#include <QHeaderView>
#include <QMessageBox>
#include <QStackedWidget>
#include <QGroupBox>
#include <QButtonGroup>
#include <QSplitter>
#include <QListWidget>
#include <QTableWidget>
#include <QAbstractItemView>
#include <QCheckBox>
#include <QPainterPath>
#include <QMap>
#include <QHBoxLayout>
#include <QLabel>
#include <QDialog>
#include <QScrollArea>
#include <QVBoxLayout>
#include <QPushButton>
#include <QIcon>
#include <QFrame>
#include <QAction>
#include <QListView>
#include <QFontMetrics>
#include <QTextEdit>
#include <QTextBrowser>
#include <QPdfWriter>
#include <QFileDialog>
#include <QDateTime>
#include <QPixmap>
#include <QDebug>
#include <QTimer>
#include <QMenu>
#include <QMenuBar>
#include <QResizeEvent>
#include <QMouseEvent>
#include <QRegularExpression>
#include <QApplication>
#include <QPalette>
#include <QScreen>
#include <algorithm>
#include <QPainter>
#include <QLinearGradient>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QAuthenticator>
#include <QHttpMultiPart>
#include <QCompleter>
#include <QStringListModel>
#include <QSslCertificate>
#include <QSslConfiguration>
#include <QSslSocket>
#include <QSslError>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QDesktopServices>
#include <QDir>
#include <QFormLayout>
#include <QDialogButtonBox>
#include <QProcess>
#include <QTemporaryFile>
#include <epan/plugin_if.h>
#include <cfile.h>

extern "C" void* extract_capture_file(capture_file *cf, void *user_data);

/* ── Plugin version — single source of truth ───────────────────────────── */
static constexpr char PC_VERSION[] = "v.0.5.4";

/* ------------------------------------------------------------------ */
/* Theme detection: uses the same logic as Wireshark's ColorUtils::   */
/* themeIsDark() — compare palette text lightness vs window lightness. */
/* This respects OS dark mode AND Wireshark's own colour-scheme pref. */
/* ------------------------------------------------------------------ */
static bool isDarkTheme()
{
    return qApp->palette().windowText().color().lightness() >
           qApp->palette().window().color().lightness();
}

/* Accent colour pulled live from the host (Wireshark) palette so PacketCircle's
 * chrome matches whatever blue Wireshark uses for selected rows — on any theme
 * or platform. Falls back to a Wireshark-ish blue if the palette is unset. */
static QColor pcAccentColor()
{
    QColor accent = qApp->palette().color(QPalette::Highlight);
    if (!accent.isValid() || (accent.red() == 0 && accent.green() == 0 && accent.blue() == 0))
        accent = QColor(0x33, 0x7a, 0xCC);
    return accent;
}

/* Draw a crisp outline (stroked, no fill) toolbar icon by name. Avoids any
 * QtSvg dependency — paths mirror the restyle mockup, drawn in a 24-unit space
 * and scaled to a 16 px logical icon at 2x for retina sharpness. */
static QIcon pcOutlineIcon(const QString &name, const QColor &color)
{
    const int   S   = 16;
    const qreal dpr = 2.0;
    QPixmap pm(int(S * dpr), int(S * dpr));
    pm.setDevicePixelRatio(dpr);
    pm.fill(Qt::transparent);

    QPainter p(&pm);
    p.setRenderHint(QPainter::Antialiasing, true);
    p.scale(S / 24.0, S / 24.0);
    QPen pen(color, 2.0);
    pen.setCapStyle(Qt::RoundCap);
    pen.setJoinStyle(Qt::RoundJoin);
    p.setPen(pen);
    p.setBrush(Qt::NoBrush);

    if (name == "filter") {
        QPainterPath path;
        path.moveTo(3, 5);  path.lineTo(21, 5); path.lineTo(14, 13);
        path.lineTo(14, 18); path.lineTo(10, 20); path.lineTo(10, 12);
        path.closeSubpath();
        p.drawPath(path);
    } else if (name == "clear") {
        p.drawLine(QPointF(6, 6),  QPointF(18, 18));
        p.drawLine(QPointF(18, 6), QPointF(6, 18));
    } else if (name == "reload") {
        QRectF r(4, 4, 16, 16);
        QPainterPath arc;
        arc.arcMoveTo(r, 70);
        arc.arcTo(r, 70, 280);
        p.drawPath(arc);
        /* arrow head at the arc start (70 deg) */
        qreal a = qDegreesToRadians(70.0);
        QPointF tip(12.0 + 8.0 * qCos(a), 12.0 - 8.0 * qSin(a));
        p.drawLine(tip, tip + QPointF(-3.5, -1.0));
        p.drawLine(tip, tip + QPointF(0.5, -4.0));
    } else if (name == "pdf") {
        QPainterPath path;
        path.moveTo(7, 3); path.lineTo(14, 3); path.lineTo(19, 8);
        path.lineTo(19, 21); path.lineTo(7, 21); path.closeSubpath();
        p.drawPath(path);
        QPainterPath fold;
        fold.moveTo(14, 3); fold.lineTo(14, 8); fold.lineTo(19, 8);
        p.drawPath(fold);
    } else if (name == "send") {
        QPainterPath path;
        path.moveTo(3, 12); path.lineTo(21, 4); path.lineTo(13, 22);
        path.lineTo(11, 15); path.closeSubpath();
        p.drawPath(path);
    } else if (name == "search") {
        p.drawEllipse(QPointF(11, 11), 7.0, 7.0);
        p.drawLine(QPointF(21, 21), QPointF(16.5, 16.5));
    } else if (name == "help") {
        p.drawEllipse(QPointF(12, 12), 9.0, 9.0);
        QPainterPath q;
        q.moveTo(9, 9.5);
        q.cubicTo(9, 6.5, 15, 6.5, 14.5, 10);
        q.cubicTo(14.2, 12, 12, 12, 12, 14.5);
        p.drawPath(q);
        p.drawPoint(QPointF(12, 17.5));
    }
    p.end();
    return QIcon(pm);
}

/* Shared context-menu stylesheet — themed (light/dark) with the palette accent.
 * Used by every PacketCircle popup menu so they look like one app. */
static QString pcMenuStyleSheet()
{
    const bool dark = isDarkTheme();
    return QString(
        "QMenu {"
        "  background: %1;"
        "  color: %2;"
        "  border: 1px solid %3;"
        "  border-radius: 8px;"
        "  padding: 5px;"
        "}"
        "QMenu::item {"
        "  padding: 6px 16px;"
        "  border-radius: 5px;"
        "  margin: 1px 2px;"
        "}"
        "QMenu::item:selected { background: %4; color: white; }"
        "QMenu::item:disabled { color: %5; }"
        "QMenu::separator { height: 1px; background: %3; margin: 4px 8px; }"
    )
    .arg(dark ? "#2b2b2b" : "#f6f6f6")
    .arg(dark ? "#e4e4e4" : "#1f1f1f")
    .arg(dark ? "#4a4a4a" : "#c4c4c4")
    .arg(pcAccentColor().name())
    .arg(dark ? "#666"    : "#aaa");
}

/* ── Tier 3: Analysis result cache ─────────────────────────────────────────
 * Caches the result of expensive full-capture scans so repeated clicks on
 * the same connection pair return instantly.
 * Key format:  "L2|src|dst"   /  "TCP|src|dst|port"  /  "UDP|src|dst|port"
 * Lifetime: cleared whenever a new analysis result arrives (new capture /
 *           display-filter change), so stale results are never shown.       */
namespace {
struct AnalysisCache {
    QHash<QString, l2_info_t*>       l2;
    QHash<QString, tcp_stat_info_t*> tcpStat;
    QHash<QString, udp_stat_info_t*> udpStat;

    void clear() {
        for (auto *v : std::as_const(l2))      packet_analyzer_free_l2_info(v);
        for (auto *v : std::as_const(tcpStat)) packet_analyzer_free_tcp_stat_info(v);
        for (auto *v : std::as_const(udpStat)) packet_analyzer_free_udp_stat_info(v);
        l2.clear(); tcpStat.clear(); udpStat.clear();
    }

    static QString l2Key(const char *a, const char *b)
        { return QString("L2|%1|%2").arg(a, b); }
    static QString tcpKey(const char *a, const char *b, quint16 port)
        { return QString("TCP|%1|%2|%3").arg(a, b, QString::number(port)); }
    static QString udpKey(const char *a, const char *b, quint16 port)
        { return QString("UDP|%1|%2|%3").arg(a, b, QString::number(port)); }
};
static AnalysisCache s_analysisCache;
} // namespace

static bool parse_ipv4(const QString &ip, quint32 *out)
{
    QStringList parts = ip.split('.', Qt::SkipEmptyParts);
    if (parts.size() != 4)
        return false;
    quint32 value = 0;
    for (const QString &part : parts) {
        bool ok = false;
        int octet = part.toInt(&ok);
        if (!ok || octet < 0 || octet > 255)
            return false;
        value = (value << 8) | (quint32)octet;
    }
    *out = value;
    return true;
}

static bool parse_cidr(const QString &cidr, quint32 *base, int *prefix_len)
{
    QStringList parts = cidr.split('/', Qt::SkipEmptyParts);
    if (parts.size() != 2)
        return false;
    bool ok = false;
    int prefix = parts[1].toInt(&ok);
    if (!ok || prefix < 0 || prefix > 32)
        return false;
    quint32 ip_value = 0;
    if (!parse_ipv4(parts[0], &ip_value))
        return false;
    if (base)
        *base = ip_value;
    if (prefix_len)
        *prefix_len = prefix;
    return true;
}

static bool ipv4_in_cidr(const QString &ip, const QString &cidr)
{
    quint32 ip_value = 0;
    if (!parse_ipv4(ip, &ip_value))
        return false;
    quint32 base = 0;
    int prefix = 0;
    if (!parse_cidr(cidr, &base, &prefix))
        return false;
    quint32 mask = prefix == 0 ? 0 : 0xFFFFFFFFu << (32 - prefix);
    return (ip_value & mask) == (base & mask);
}

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , m_centralWidget(nullptr)
    , m_mainLayout(nullptr)
    , m_controlsWidget(nullptr)
    , m_controlsOuterLayout(nullptr)
    , m_controlsRow1(nullptr)
    , m_controlsRow2(nullptr)
    , m_row1Widget(nullptr)
    , m_row2Widget(nullptr)
    , m_top10Btn(nullptr)
    , m_top25Btn(nullptr)
    , m_top50Btn(nullptr)
    , m_packetsBtn(nullptr)
    , m_bytesBtn(nullptr)
    , m_circleBtn(nullptr)
    , m_tableBtn(nullptr)
    , m_graphBtn(nullptr)
    , m_macBtn(nullptr)
    , m_ipBtn(nullptr)
    , m_applyFilterBtn(nullptr)
    , m_clearFilterBtn(nullptr)
    , m_reloadDataBtn(nullptr)
    , m_savePDFBtn(nullptr)
    , m_sendToNtopBtn(nullptr)
    , m_sendToMalcolmBtn(nullptr)
    , m_settingsBtn(nullptr)
    , m_ntopEnabled(true)
    , m_malcolmEnabled(false)
    , m_splitter(nullptr)
    , m_splitterSizesRestored(false)
    , m_graphControlsRow(nullptr)
    , m_graphEdgeColorCombo(nullptr)
    , m_graphNodeColorCombo(nullptr)
    , m_graphLayoutCombo(nullptr)
    , m_viewStack(nullptr)
    , m_circleWidget(nullptr)
    , m_circleContainer(nullptr)
    , m_graphWidget(nullptr)
    , m_searchLineEdit(nullptr)
    , m_tableWidget(nullptr)
    , m_pairListWidget(nullptr)
    , m_pairListContainer(nullptr)
    , m_legendWidget(nullptr)
    , m_legendLayout(nullptr)
    , m_legendRow2Layout(nullptr)
    , m_lineThicknessCheckBox(nullptr)
    , m_pairListBlinkTimer(nullptr)
    , m_pairListBlinkState(false)
    , m_hoveredPairListItem(nullptr)
    , m_connectionPopup(nullptr)
    , m_networkManager(nullptr)
    , m_analysisResult(NULL)
    , m_top_pairs(NULL)
    , m_circle_pairs(NULL)
    , m_searchOverridePairs(NULL)
    , m_searchOverrideMode(false)
    , m_savedTopN(10)
    , m_topN(10)
    , m_useBytes(FALSE)
    , m_useMAC(FALSE)
    , m_darkTheme(isDarkTheme())
    , m_wifiMode(false)
    , m_betaGraphEnabled(false)
    , m_enableL2Analysis(true)
    , m_enableTransportStats(true)
    , m_enableDeepInspection(true)
    , m_activeThresholdGroup(0)
    , m_activeWifiThresholdGroup(0)
    , m_reportCompany("Demo")
    , m_reportPreparedBy("John Doe")
    , m_reportProject("")
    , m_reportComments("Demo Segment Analysis")
    , m_reportPaperSize(0)
{
    m_thresholdGroups.append(GraphWidget::GraphThresholds::defaults());
    m_wifiThresholdGroups.append(CircleWidget::WifiThresholds::defaults());
    m_internalSubnets = GraphWidget::defaultInternalSubnets();
    setupUI();
}

MainWindow::~MainWindow()
{
    /* Clear CircleWidget first to avoid dangling pointers */
    if (m_circleWidget) {
        m_circleWidget->setPairs(NULL, NULL);
    }
    
    /* Free circle_pairs list (only the list nodes, pairs are owned by m_analysisResult) */
    if (m_circle_pairs) {
        g_list_free(m_circle_pairs);  /* Free list nodes only, not the pairs */
        m_circle_pairs = NULL;
    }
    
    /* Don't free m_top_pairs - it contains pointers to pairs owned by m_analysisResult */
    /* The list nodes will be cleaned up when m_analysisResult is freed */
    m_top_pairs = NULL;
    
    if (m_analysisResult) {
        packet_analyzer_free_result(m_analysisResult);
    }
}

/* --- Preferences persistence (stored in ~/.PacketCircle/settings.ini) --- */

QString MainWindow::preferencesFilePath() const
{
    QString dir = QDir::homePath() + QDir::separator() + ".PacketCircle";
    return dir + QDir::separator() + "settings.ini";
}

void MainWindow::savePreferences()
{
    /* Ensure the .PacketCircle directory exists */
    QString dir = QDir::homePath() + QDir::separator() + ".PacketCircle";
    QDir().mkpath(dir);

    QSettings settings(preferencesFilePath(), QSettings::IniFormat);

    /* Window geometry */
    settings.beginGroup("Window");
    settings.setValue("geometry", saveGeometry());
    settings.setValue("pos", pos());
    settings.setValue("size", size());
    if (m_splitter) {
        settings.setValue("splitterSizes", QVariant::fromValue(m_splitter->sizes()));
    }
    settings.endGroup();

    /* Display preferences */
    settings.beginGroup("Display");
    settings.setValue("topN", (int)m_topN);
    settings.setValue("useBytes", (bool)m_useBytes);
    settings.setValue("useMAC", (bool)m_useMAC);
    settings.setValue("view", m_viewStack ? m_viewStack->currentIndex() : 0);
    if (m_lineThicknessCheckBox) {
        settings.setValue("lineThickness", m_lineThicknessCheckBox->isChecked());
    }
    settings.endGroup();

    /* Integration toggles */
    settings.beginGroup("Integrations");
    settings.setValue("ntop_enabled",    m_ntopEnabled);
    settings.setValue("malcolm_enabled", m_malcolmEnabled);
    settings.endGroup();

    /* Performance toggles */
    settings.beginGroup("Performance");
    settings.setValue("enable_l2_analysis",     m_enableL2Analysis);
    settings.setValue("enable_transport_stats", m_enableTransportStats);
    settings.setValue("enable_deep_inspection", m_enableDeepInspection);

    /* Graph threshold groups */
    saveThresholdGroups();
    settings.setValue("active_threshold_group", m_activeThresholdGroup);

    /* WiFi threshold groups */
    saveWifiThresholdGroups();
    settings.setValue("active_wifi_threshold_group", m_activeWifiThresholdGroup);
    settings.endGroup();

    /* Report configuration */
    settings.beginGroup("Report");
    settings.setValue("company",     m_reportCompany);
    settings.setValue("prepared_by", m_reportPreparedBy);
    settings.setValue("project",     m_reportProject);
    settings.setValue("comments",    m_reportComments);
    settings.setValue("paper_size",  m_reportPaperSize);
    settings.endGroup();

    settings.beginGroup("Network");
    QStringList snEntries;
    for (const auto &sn : m_internalSubnets)
        snEntries.append(QString("%1/%2:%3").arg(sn.prefix).arg(sn.bits)
                         .arg(sn.builtIn ? "builtin" : "custom"));
    settings.setValue("internalSubnets", snEntries);
    settings.endGroup();

    /* Graph view combo selections */
    settings.beginGroup("Graph");
    if (m_graphEdgeColorCombo) settings.setValue("edgeColor", m_graphEdgeColorCombo->currentIndex());
    if (m_graphNodeColorCombo) settings.setValue("nodeColor", m_graphNodeColorCombo->currentIndex());
    if (m_graphLayoutCombo)    settings.setValue("layout",    m_graphLayoutCombo->currentIndex());
    settings.endGroup();

    settings.sync();
}

void MainWindow::loadPreferences()
{
    QString path = preferencesFilePath();
    if (!QFile::exists(path))
        return;  /* First launch - use defaults */

    QSettings settings(path, QSettings::IniFormat);

    /* Window geometry */
    settings.beginGroup("Window");
    QByteArray geom = settings.value("geometry").toByteArray();
    if (!geom.isEmpty()) {
        restoreGeometry(geom);
    } else {
        /* Fallback: use explicit pos/size if geometry blob is missing */
        QPoint savedPos = settings.value("pos", QPoint()).toPoint();
        QSize savedSize = settings.value("size", QSize()).toSize();
        if (savedSize.isValid() && !savedSize.isNull()) {
            resize(savedSize);
        }
        if (!savedPos.isNull()) {
            move(savedPos);
        }
    }
    QList<QVariant> splitterVar = settings.value("splitterSizes").toList();
    if (!splitterVar.isEmpty() && m_splitter) {
        QList<int> sizes;
        for (const QVariant &v : splitterVar)
            sizes.append(v.toInt());
        if (sizes.size() == 2 && sizes[0] > 0 && sizes[1] > 0) {
            m_splitter->setSizes(sizes);
            m_splitterSizesRestored = true;
        }
    }
    settings.endGroup();

    /* Display preferences */
    settings.beginGroup("Display");

    int topN = settings.value("topN", 10).toInt();
    if (topN == 25) {
        m_topN = 25;
        if (m_top10Btn) m_top10Btn->setChecked(false);
        if (m_top25Btn) m_top25Btn->setChecked(true);
        if (m_top50Btn) m_top50Btn->setChecked(false);
    } else if (topN == 50) {
        m_topN = 50;
        if (m_top10Btn) m_top10Btn->setChecked(false);
        if (m_top25Btn) m_top25Btn->setChecked(false);
        if (m_top50Btn) m_top50Btn->setChecked(true);
    } else {
        m_topN = 10;
        if (m_top10Btn) m_top10Btn->setChecked(true);
        if (m_top25Btn) m_top25Btn->setChecked(false);
        if (m_top50Btn) m_top50Btn->setChecked(false);
    }

    bool useBytes = settings.value("useBytes", false).toBool();
    m_useBytes = useBytes ? TRUE : FALSE;
    if (m_packetsBtn) m_packetsBtn->setChecked(!useBytes);
    if (m_bytesBtn) m_bytesBtn->setChecked(useBytes);

    bool useMAC = settings.value("useMAC", false).toBool();
    m_useMAC = useMAC ? TRUE : FALSE;
    if (m_ipBtn) m_ipBtn->setChecked(!useMAC);
    if (m_macBtn) m_macBtn->setChecked(useMAC);
    updateSearchBarForMode();

    int viewIdx = settings.value("view", 0).toInt();
    if (m_viewStack && viewIdx >= 0 && viewIdx <= 2) {
        m_viewStack->setCurrentIndex(viewIdx);
        if (m_circleBtn) m_circleBtn->setChecked(viewIdx == 0);
        if (m_tableBtn)  m_tableBtn->setChecked(viewIdx == 1);
        if (m_graphBtn)  m_graphBtn->setChecked(viewIdx == 2);
        if (m_graphControlsRow) m_graphControlsRow->setVisible(viewIdx == 2);
    }

    bool lineThickness = settings.value("lineThickness", false).toBool();
    if (m_lineThicknessCheckBox) {
        m_lineThicknessCheckBox->setChecked(lineThickness);
    }

    settings.endGroup();

    /* Integration toggles */
    settings.beginGroup("Integrations");
    m_ntopEnabled    = settings.value("ntop_enabled",    true).toBool();
    m_malcolmEnabled = settings.value("malcolm_enabled", false).toBool();
    settings.endGroup();

    /* Apply visibility immediately */
    if (m_sendToNtopBtn)    m_sendToNtopBtn->setVisible(m_ntopEnabled);
    if (m_sendToMalcolmBtn) m_sendToMalcolmBtn->setVisible(m_malcolmEnabled);

    /* Performance toggles */
    settings.beginGroup("Performance");
    m_enableL2Analysis     = settings.value("enable_l2_analysis",     true).toBool();
    m_enableTransportStats = settings.value("enable_transport_stats",  true).toBool();
    m_enableDeepInspection = settings.value("enable_deep_inspection",  true).toBool();

    /* Graph threshold groups */
    loadThresholdGroups();
    m_activeThresholdGroup = settings.value("active_threshold_group", 0).toInt();
    if (m_activeThresholdGroup < 0 || m_activeThresholdGroup >= m_thresholdGroups.size())
        m_activeThresholdGroup = 0;

    /* WiFi threshold groups */
    loadWifiThresholdGroups();
    m_activeWifiThresholdGroup = settings.value("active_wifi_threshold_group", 0).toInt();
    if (m_activeWifiThresholdGroup < 0 || m_activeWifiThresholdGroup >= m_wifiThresholdGroups.size())
        m_activeWifiThresholdGroup = 0;
    if (m_circleWidget)
        m_circleWidget->setWifiThresholds(m_wifiThresholdGroups[m_activeWifiThresholdGroup]);
    settings.endGroup();

    /* Report configuration */
    settings.beginGroup("Report");
    m_reportCompany    = settings.value("company",     "Demo").toString();
    m_reportPreparedBy = settings.value("prepared_by", "John Doe").toString();
    m_reportProject    = settings.value("project",     "").toString();
    m_reportComments   = settings.value("comments",    "Demo Segment Analysis").toString();
    m_reportPaperSize  = settings.value("paper_size",  0).toInt();
    settings.endGroup();

    settings.beginGroup("Network");
    QStringList snEntries = settings.value("internalSubnets").toStringList();
    if (!snEntries.isEmpty()) {
        m_internalSubnets.clear();
        for (const QString &e : snEntries) {
            QStringList tok = e.split(':');
            if (tok.size() < 1) continue;
            QStringList addrBits = tok[0].split('/');
            if (addrBits.size() != 2) continue;
            GraphWidget::InternalSubnet sn;
            sn.prefix  = addrBits[0].trimmed();
            sn.bits    = addrBits[1].trimmed().toInt();
            sn.builtIn = (tok.size() >= 2 && tok[1].trimmed() == "builtin");
            if (sn.bits > 0 && sn.bits <= 32)
                m_internalSubnets.append(sn);
        }
    }
    settings.endGroup();
    if (m_graphWidget) m_graphWidget->setInternalSubnets(m_internalSubnets);

    /* Graph view combo selections — restored after combos and m_graphWidget both exist */
    settings.beginGroup("Graph");
    if (m_graphEdgeColorCombo)
        m_graphEdgeColorCombo->setCurrentIndex(
            qBound(0, settings.value("edgeColor", 0).toInt(),
                   m_graphEdgeColorCombo->count() - 1));
    if (m_graphNodeColorCombo)
        m_graphNodeColorCombo->setCurrentIndex(
            qBound(0, settings.value("nodeColor", 0).toInt(),
                   m_graphNodeColorCombo->count() - 1));
    if (m_graphLayoutCombo)
        m_graphLayoutCombo->setCurrentIndex(
            qBound(0, settings.value("layout", (int)GraphWidget::LAYOUT_STAR).toInt(),
                   m_graphLayoutCombo->count() - 1));
    settings.endGroup();

    /* Beta features — graph view is hidden until opted in via settings.ini */
    settings.beginGroup("Beta");
    m_betaGraphEnabled = settings.value("EnableGraphView", false).toBool();
    settings.endGroup();
    if (m_graphBtn) m_graphBtn->setVisible(m_betaGraphEnabled);
    /* If graph was the saved view but beta is now disabled, fall back to circle */
    if (!m_betaGraphEnabled && m_viewStack && m_viewStack->currentIndex() == 2) {
        m_viewStack->setCurrentIndex(0);
        if (m_circleBtn) m_circleBtn->setChecked(true);
        if (m_graphControlsRow) m_graphControlsRow->setVisible(false);
    }
}

void MainWindow::closeEvent(QCloseEvent *event)
{
    savePreferences();
    QMainWindow::closeEvent(event);
}

/* --- End preferences --- */

void MainWindow::setupUI()
{
    m_centralWidget = new QWidget(this);
    setCentralWidget(m_centralWidget);
    m_mainLayout = new QVBoxLayout(m_centralWidget);

    createControls();
    createCircleView();
    createTableView();
    /* Legend will be created in createTableView after pair list container is ready */

    /* Graph view */
    m_graphWidget = new GraphWidget(this);
    m_graphWidget->setDarkTheme(m_darkTheme);
    connect(m_graphWidget, &GraphWidget::pairSelectionChanged,
            this, &MainWindow::onPairSelectionChanged);
    connect(m_graphWidget, &GraphWidget::nodeVisibilityToggle,
            this, &MainWindow::onNodeVisibilityToggle);
    connect(m_graphWidget, &GraphWidget::lineClicked,
            this, &MainWindow::onLineClicked);
    connect(m_graphWidget, &GraphWidget::lineHovered,
            this, &MainWindow::onLineHovered);
    connect(m_graphWidget, &GraphWidget::legendFilterChanged,
            this, &MainWindow::onGraphLegendFilter);

    /* Create view stack: Page 0=Circle, 1=Table, 2=Graph */
    m_viewStack = new QStackedWidget(this);
    m_viewStack->addWidget(m_circleContainer);  /* Page 0 */
    m_viewStack->addWidget(m_tableWidget);      /* Page 1 */
    m_viewStack->addWidget(m_graphWidget);      /* Page 2 */
    m_viewStack->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    
    /* Create splitter for main content */
    m_splitter = new QSplitter(Qt::Horizontal, this);
    m_splitter->addWidget(m_viewStack);
    m_splitter->addWidget(m_pairListContainer);
    
    /* Set stretch factors - circle area stretches more, pair list less */
    m_splitter->setStretchFactor(0, 1);  /* Circle container - takes extra space */
    m_splitter->setStretchFactor(1, 0);  /* Pair list container - stays near its size */
    
    /* Make splitter handle visible and easy to grab on all platforms */
#ifdef Q_OS_WIN
    m_splitter->setHandleWidth(8);
#else
    m_splitter->setHandleWidth(5);
#endif
    if (m_darkTheme) {
        m_splitter->setStyleSheet(
            "QSplitter::handle { background-color: #555; }"
            "QSplitter::handle:hover { background-color: #777; }"
        );
    } else {
        m_splitter->setStyleSheet(
            "QSplitter::handle { background-color: #ccc; }"
            "QSplitter::handle:hover { background-color: #aaa; }"
        );
    }
    m_splitter->setChildrenCollapsible(false);
    
    /* Set initial sizes: 68/32 split - circle gets majority of space */
    m_splitter->setSizes(QList<int>() << 680 << 320);

    /* Refresh MAC address display when the pair list panel is resized */
    connect(m_splitter, &QSplitter::splitterMoved, this, &MainWindow::refreshPairListText);

    m_mainLayout->addWidget(m_splitter);
    
    /* Set initial view */
    m_circleBtn->setChecked(true);
    m_viewStack->setCurrentIndex(0);
    if (m_graphControlsRow) m_graphControlsRow->setVisible(false);
    
    /* Make window resizable with a reasonable minimum size
     * 640x480 fits older laptops; 1280x780 is comfortable on 1080p */
    setMinimumSize(640, 480);
    resize(1280, 780);
    
    /* Set window title and flags */
setWindowTitle(QString("PacketCircle %1").arg(QLatin1String(PC_VERSION)));
    
    /* Create pair list blink timer for synchronized search highlighting */
    m_pairListBlinkTimer = new QTimer(this);
    m_pairListBlinkTimer->setInterval(500);
    connect(m_pairListBlinkTimer, &QTimer::timeout, this, &MainWindow::onPairListBlinkTimer);

    /* Restore user preferences from ~/.PacketCircle/settings.ini */
    loadPreferences();
}

void MainWindow::createControls()
{
    m_controlsWidget = new QWidget(this);
    m_controlsWidget->setObjectName("controlsToolbar");

    /* ---- Segmented-control geometry (shared by both themes) ----
     * Each group sits in a recessed "track" (#segTrack); the buttons are
     * borderless chips inside it. Colours come from the per-theme styles. */
    static const char *segmentShapeRules =
        "#controlsToolbar #segTrack {"
        "  border-radius: 7px;"
        "}"
        "#controlsToolbar QPushButton[segmented=\"true\"] {"
        "  border: none;"
        "  border-radius: 5px;"
        "  padding: 4px 12px;"
        "  font-size: 11px;"
        "  font-weight: bold;"
        "  min-height: 22px;"
        "}";

    /* ---- Dark theme toolbar ---- */
    static const char *darkToolbarStyle =
        "#controlsToolbar {"
        "  background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #3a3a3a, stop:1 #2b2b2b);"
        "  border: 1px solid #222;"
        "  border-radius: 4px;"
        "  padding: 4px;"
        "}"
        "#controlsToolbar #segTrack {"
        "  background: #232323;"
        "  border: 1px solid #454545;"
        "}"
        "#controlsToolbar QPushButton[segmented=\"true\"] {"
        "  background: transparent;"
        "  color: #cfcfcf;"
        "}"
        "#controlsToolbar QPushButton[segmented=\"true\"]:checked {"
        "  background: #0078d4;"
        "  color: white;"
        "}"
        "#controlsToolbar QPushButton[segmented=\"true\"]:hover {"
        "  background: rgba(255,255,255,0.06);"
        "}"
        "#controlsToolbar QPushButton[segmented=\"true\"]:checked:hover {"
        "  background: #1a8ae8;"
        "}"
        "#controlsToolbar QPushButton[action=\"true\"] {"
        "  background: transparent;"
        "  color: #c0c0c0;"
        "  border: 1px solid transparent;"
        "  border-radius: 3px;"
        "  padding: 4px 10px;"
        "  font-size: 11px;"
        "  min-height: 22px;"
        "}"
        "#controlsToolbar QPushButton[action=\"true\"]:hover {"
        "  background: #4a4a4a;"
        "  border-color: #666;"
        "  color: #ffffff;"
        "}"
        "#controlsToolbar QPushButton[action=\"true\"]:pressed {"
        "  background: #333;"
        "}"
        "#controlsToolbar QCheckBox {"
        "  color: #d0d0d0;"
        "  font-size: 11px;"
        "  spacing: 4px;"
        "}"
        "#controlsToolbar QLineEdit {"
        "  background: #444;"
        "  color: #e0e0e0;"
        "  border: 1px solid #666;"
        "  border-radius: 3px;"
        "  padding: 3px 6px;"
        "  font-size: 11px;"
        "  min-height: 22px;"
        "  selection-background-color: #0078d4;"
        "}"
        "#controlsToolbar QLineEdit:focus {"
        "  border-color: #0078d4;"
        "}"
        "#controlsToolbar QLabel {"
        "  color: #a0a0a0;"
        "  font-size: 10px;"
        "}";

    /* ---- Light theme toolbar ---- */
    static const char *lightToolbarStyle =
        "#controlsToolbar {"
        "  background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #f0f0f0, stop:1 #dcdcdc);"
        "  border: 1px solid #b0b0b0;"
        "  border-radius: 4px;"
        "  padding: 4px;"
        "}"
        "#controlsToolbar #segTrack {"
        "  background: #e6e6e6;"
        "  border: 1px solid #c0c0c0;"
        "}"
        "#controlsToolbar QPushButton[segmented=\"true\"] {"
        "  background: transparent;"
        "  color: #444;"
        "}"
        "#controlsToolbar QPushButton[segmented=\"true\"]:checked {"
        "  background: #0078d4;"
        "  color: white;"
        "}"
        "#controlsToolbar QPushButton[segmented=\"true\"]:hover {"
        "  background: rgba(0,0,0,0.06);"
        "}"
        "#controlsToolbar QPushButton[segmented=\"true\"]:checked:hover {"
        "  background: #1a8ae8;"
        "}"
        "#controlsToolbar QPushButton[action=\"true\"] {"
        "  background: transparent;"
        "  color: #444;"
        "  border: 1px solid transparent;"
        "  border-radius: 3px;"
        "  padding: 4px 10px;"
        "  font-size: 11px;"
        "  min-height: 22px;"
        "}"
        "#controlsToolbar QPushButton[action=\"true\"]:hover {"
        "  background: #d0d0d0;"
        "  border-color: #aaa;"
        "  color: #111;"
        "}"
        "#controlsToolbar QPushButton[action=\"true\"]:pressed {"
        "  background: #c0c0c0;"
        "}"
        "#controlsToolbar QCheckBox {"
        "  color: #333;"
        "  font-size: 11px;"
        "  spacing: 4px;"
        "}"
        "#controlsToolbar QLineEdit {"
        "  background: #fff;"
        "  color: #222;"
        "  border: 1px solid #aaa;"
        "  border-radius: 3px;"
        "  padding: 3px 6px;"
        "  font-size: 11px;"
        "  min-height: 22px;"
        "  selection-background-color: #0078d4;"
        "}"
        "#controlsToolbar QLineEdit:focus {"
        "  border-color: #0078d4;"
        "}"
        "#controlsToolbar QLabel {"
        "  color: #666;"
        "  font-size: 10px;"
        "}";

    QString style = QString(m_darkTheme ? darkToolbarStyle : lightToolbarStyle) + segmentShapeRules;
    /* Swap the hardcoded Office-blue tokens for the host (Wireshark) accent so the
     * toolbar's active segment matches the app. Covers checked bg, checked border,
     * checked-hover, and the QLineEdit selection/focus colour in both themes. */
    QColor accent = pcAccentColor();
    style.replace("#0078d4", accent.name());
    style.replace("#005a9e", accent.darker(125).name());
    style.replace("#1a8ae8", accent.lighter(115).name());

    /* ---- Row 2 / Row 3 component styling (themed) ---- */
    const bool dk = m_darkTheme;
    QString row23 = QString(
        /* primary action (Filter) — accent-filled */
        "#controlsToolbar QPushButton[action=\"true\"][primary=\"true\"] {"
        "  background: %1; color: white; font-weight: bold; border: none;"
        "}"
        "#controlsToolbar QPushButton[action=\"true\"][primary=\"true\"]:hover { background: %2; }"
        /* search field */
        "#controlsToolbar QLineEdit#searchField {"
        "  background: %3; border: 1px solid %4; border-radius: 8px;"
        "  padding: 4px 8px; color: %5; min-height: 22px;"
        "}"
        "#controlsToolbar QLineEdit#searchField:focus { border-color: %1; }"
        /* thin vertical divider */
        "#controlsToolbar QFrame#vdiv { background: %4; max-width: 1px; border: none; }"
        /* field chip (Edge / Node / Layout) */
        "#controlsToolbar QFrame#fieldChip {"
        "  background: %6; border: 1px solid %4; border-radius: 7px;"
        "}"
        "#controlsToolbar QLabel#fieldKey {"
        "  color: %7; font-size: 10px; font-weight: bold; padding: 0 7px;"
        "}"
        "#controlsToolbar QFrame#fieldChip QComboBox {"
        "  background: transparent; border: none; border-left: 1px solid %4;"
        "  padding: 4px 6px 4px 8px; color: %5; font-size: 11px; min-height: 22px;"
        "}"
        "#controlsToolbar QFrame#fieldChip QComboBox::drop-down { border: none; width: 18px; }"
        "#controlsToolbar QComboBox QAbstractItemView {"
        "  background: %8; color: %5; border: 1px solid %4; border-radius: 6px;"
        "  selection-background-color: %1; selection-color: white; outline: none;"
        "  padding: 4px;"
        "}"
        "#controlsToolbar QComboBox QAbstractItemView::item {"
        "  min-height: 22px; padding: 4px 10px; border-radius: 4px;"
        "}"
        "#controlsToolbar QComboBox QAbstractItemView::item:selected {"
        "  background: %1; color: white;"
        "}"
        /* re-layout action button */
        "#controlsToolbar QPushButton#relayoutBtn {"
        "  background: transparent; color: %5; border: 1px solid %4;"
        "  border-radius: 7px; padding: 4px 12px; font-size: 11px; min-height: 22px;"
        "}"
        "#controlsToolbar QPushButton#relayoutBtn:hover { border-color: %1; color: %9; }"
        /* zoom pill */
        "#controlsToolbar QWidget#zoomPill { background: %10; border: 1px solid %4; border-radius: 7px; }"
        "#controlsToolbar QWidget#zoomPill QPushButton {"
        "  background: transparent; color: %5; border: none; border-radius: 5px;"
        "  padding: 3px 9px; font-size: 12px; min-width: 26px;"
        "}"
        "#controlsToolbar QWidget#zoomPill QPushButton:hover { background: %11; color: %9; }"
    )
    .arg(accent.name())                                       /* %1 accent          */
    .arg(accent.darker(120).name())                           /* %2 accent hover    */
    .arg(dk ? "#2a2a2a" : "#ffffff")                          /* %3 search bg       */
    .arg(dk ? "#4a4a4a" : "#b0b0b0")                          /* %4 border          */
    .arg(dk ? "#e0e0e0" : "#222222")                          /* %5 text            */
    .arg(dk ? "#2d2d2d" : "#e0e0e0")                          /* %6 chip bg         */
    .arg(dk ? "#a0a0a0" : "#666666")                          /* %7 field key       */
    .arg(dk ? "#2b2b2b" : "#f6f6f6")                          /* %8 popup bg        */
    .arg(dk ? "#ffffff" : accent.name())                      /* %9 hover text      */
    .arg(dk ? "#232323" : "#e6e6e6")                          /* %10 zoom track     */
    .arg(dk ? "rgba(255,255,255,0.06)" : "rgba(0,0,0,0.06)"); /* %11 zoom hover     */
    style += row23;

    m_controlsWidget->setStyleSheet(style);

    m_controlsOuterLayout = new QVBoxLayout(m_controlsWidget);
    m_controlsOuterLayout->setSpacing(4);
    m_controlsOuterLayout->setContentsMargins(6, 4, 6, 4);

    /* === Row 1: View/Data option groups === */
    m_row1Widget = new QWidget(m_controlsWidget);
    m_controlsRow1 = new QHBoxLayout(m_row1Widget);
    m_controlsRow1->setSpacing(12);
    m_controlsRow1->setContentsMargins(0, 0, 0, 0);

    /* Helper lambda to create a segmented button */
    auto makeSegBtn = [this](const QString &text, const QString &pos) -> QPushButton* {
        QPushButton *btn = new QPushButton(text, m_controlsWidget);
        btn->setCheckable(true);
        btn->setProperty("segmented", true);
        btn->setProperty("seg_pos", pos);
        return btn;
    };

    /* Helper lambda to create an action button */
    auto makeActionBtn = [this](const QString &text) -> QPushButton* {
        QPushButton *btn = new QPushButton(text, m_controlsWidget);
        btn->setProperty("action", true);
        return btn;
    };

    /* Helper lambda: thin vertical divider for grouping toolbar clusters. */
    auto makeVDivider = [this]() -> QFrame* {
        QFrame *d = new QFrame(m_controlsWidget);
        d->setObjectName("vdiv");
        d->setFrameShape(QFrame::VLine);
        d->setFixedWidth(1);
        return d;
    };

    /* Helper lambda: wrap a set of segmented buttons in a recessed "track" so the
     * group reads as a single pill (matches the restyle mockup). */
    auto makeSegGroup = [this](std::initializer_list<QPushButton*> btns) -> QWidget* {
        QWidget *track = new QWidget(m_controlsWidget);
        track->setObjectName("segTrack");
        track->setAttribute(Qt::WA_StyledBackground, true);
        QHBoxLayout *l = new QHBoxLayout(track);
        l->setContentsMargins(3, 3, 3, 3);
        l->setSpacing(2);
        for (QPushButton *b : btns)
            l->addWidget(b);   /* reparents b into the track */
        return track;
    };

    /* -- Top N segment group -- */
    QLabel *topLabel = new QLabel("Top:", m_controlsWidget);
    m_top10Btn = makeSegBtn("10", "left");
    m_top25Btn = makeSegBtn("25", "mid");
    m_top50Btn = makeSegBtn("50", "right");
    m_top10Btn->setChecked(true);

    QButtonGroup *topGroup = new QButtonGroup(this);
    topGroup->setExclusive(true);
    topGroup->addButton(m_top10Btn);
    topGroup->addButton(m_top25Btn);
    topGroup->addButton(m_top50Btn);

    connect(m_top10Btn, &QPushButton::clicked, this, &MainWindow::onTop10Clicked);
    connect(m_top25Btn, &QPushButton::clicked, this, &MainWindow::onTop25Clicked);
    connect(m_top50Btn, &QPushButton::clicked, this, &MainWindow::onTop50Clicked);

    /* -- Metric segment group -- */
    QLabel *metricLabel = new QLabel("Metric:", m_controlsWidget);
    m_packetsBtn = makeSegBtn("Pkts", "left");
    m_bytesBtn = makeSegBtn("Bytes", "right");
    m_packetsBtn->setChecked(true);

    QButtonGroup *metricGroup = new QButtonGroup(this);
    metricGroup->setExclusive(true);
    metricGroup->addButton(m_packetsBtn);
    metricGroup->addButton(m_bytesBtn);

    connect(m_packetsBtn, &QPushButton::clicked, this, [this]() { onPacketsToggled(true); });
    connect(m_bytesBtn, &QPushButton::clicked, this, [this]() { onBytesToggled(true); });

    /* -- View segment group -- */
    QLabel *viewLabel = new QLabel("View:", m_controlsWidget);
    m_circleBtn = makeSegBtn("Circle", "left");
    m_tableBtn  = makeSegBtn("Table",  "mid");
    m_graphBtn  = makeSegBtn("Graph",  "right");
    m_circleBtn->setChecked(true);

    QButtonGroup *viewGroup = new QButtonGroup(this);
    viewGroup->setExclusive(true);
    viewGroup->addButton(m_circleBtn);
    viewGroup->addButton(m_tableBtn);
    viewGroup->addButton(m_graphBtn);

    connect(m_circleBtn, &QPushButton::clicked, this, [this]() { onCircleViewToggled(true); });
    connect(m_tableBtn,  &QPushButton::clicked, this, [this]() { onTableViewToggled(true); });
    connect(m_graphBtn,  &QPushButton::clicked, this, [this]() { onGraphViewToggled(true); });

    /* -- Mode segment group -- */
    QLabel *modeLabel = new QLabel("Mode:", m_controlsWidget);
    m_ipBtn = makeSegBtn("IP", "left");
    m_macBtn = makeSegBtn("MAC", "right");
    m_ipBtn->setChecked(true);

    QButtonGroup *modeGroup = new QButtonGroup(this);
    modeGroup->setExclusive(true);
    modeGroup->addButton(m_ipBtn);
    modeGroup->addButton(m_macBtn);

    connect(m_ipBtn, &QPushButton::clicked, this, [this]() { onIPToggled(true); });
    connect(m_macBtn, &QPushButton::clicked, this, [this]() { onMACToggled(true); });

    /* -- Shared style factory for small circular icon buttons (gear + help) -- */
    auto makeIconBtn = [&](const QString &label, const QString &tip, QWidget *parent) {
        QPushButton *btn = new QPushButton(label, parent);
        btn->setToolTip(tip);
        btn->setFixedSize(26, 26);
        btn->setStyleSheet(
            QString("QPushButton {"
            "  background: %1;"
            "  color: %2;"
            "  border: 1px solid %3;"
            "  border-radius: 13px;"
            "  font-weight: bold;"
            "  font-size: 14px;"
            "}"
            "QPushButton:hover {"
            "  border-color: %4;"
            "  color: %4;"
            "}")
            .arg(m_darkTheme ? "#4a4a4a" : "#d8d8d8")
            .arg(m_darkTheme ? "#e0e0e0" : "#333")
            .arg(m_darkTheme ? "#666" : "#aaa")
            .arg(pcAccentColor().name())
        );
        return btn;
    };

    /* -- Settings (gear) button -- */
    m_settingsBtn = makeIconBtn("\u2699", "Open PacketCircle settings", m_row1Widget);
    connect(m_settingsBtn, &QPushButton::clicked, this, [this](){ showSettingsDialog(); });

    /* -- Help button -- */
    QPushButton *helpBtn = makeIconBtn("?", "Show help and controls description", m_row1Widget);
    connect(helpBtn, &QPushButton::clicked, this, &MainWindow::onHelpClicked);

    /* -- Weight checkbox -- */
    m_lineThicknessCheckBox = new QCheckBox("Weight", m_row1Widget);
    m_lineThicknessCheckBox->setToolTip("Toggle line weight: scale line thickness by traffic volume");
    m_lineThicknessCheckBox->setChecked(false);
    connect(m_lineThicknessCheckBox, &QCheckBox::toggled, this, &MainWindow::onLineThicknessToggled);

    /* Layout Row 1 — each segmented group wrapped in a recessed pill track */
    m_controlsRow1->addWidget(topLabel);
    m_controlsRow1->addWidget(makeSegGroup({m_top10Btn, m_top25Btn, m_top50Btn}));
    m_controlsRow1->addSpacing(8);
    m_controlsRow1->addWidget(metricLabel);
    m_controlsRow1->addWidget(makeSegGroup({m_packetsBtn, m_bytesBtn}));
    m_controlsRow1->addSpacing(8);
    m_controlsRow1->addWidget(viewLabel);
    m_controlsRow1->addWidget(makeSegGroup({m_circleBtn, m_tableBtn, m_graphBtn}));
    m_controlsRow1->addSpacing(8);
    m_controlsRow1->addWidget(modeLabel);
    m_controlsRow1->addWidget(makeSegGroup({m_ipBtn, m_macBtn}));
    m_controlsRow1->addSpacing(8);
    m_controlsRow1->addWidget(m_lineThicknessCheckBox);
    m_controlsRow1->addStretch();
    m_controlsRow1->addWidget(m_settingsBtn);
    m_controlsRow1->addWidget(helpBtn);

    /* === Row 2: Actions + Search === */
    m_row2Widget = new QWidget(m_controlsWidget);
    m_controlsRow2 = new QHBoxLayout(m_row2Widget);
    m_controlsRow2->setSpacing(6);
    m_controlsRow2->setContentsMargins(0, 0, 0, 0);

    /* Outline icons coloured to match the resting button text (white on the
     * accent-filled primary). */
    const QColor iconClr   = m_darkTheme ? QColor(0xC8, 0xC8, 0xC8) : QColor(0x44, 0x44, 0x44);
    const QSize  iconSz(15, 15);

    m_applyFilterBtn = makeActionBtn("Filter");
    m_applyFilterBtn->setIcon(pcOutlineIcon("filter", iconClr));
    m_applyFilterBtn->setIconSize(iconSz);
    m_clearFilterBtn = makeActionBtn("Clear");
    m_clearFilterBtn->setIcon(pcOutlineIcon("clear", iconClr));
    m_clearFilterBtn->setIconSize(iconSz);
    m_clearFilterBtn->setToolTip("Clear Wireshark display filter and show all connections");
    m_reloadDataBtn = makeActionBtn("Reload");
    m_reloadDataBtn->setIcon(pcOutlineIcon("reload", iconClr));
    m_reloadDataBtn->setIconSize(iconSz);
    m_savePDFBtn = makeActionBtn("PDF");
    m_savePDFBtn->setIcon(pcOutlineIcon("pdf", iconClr));
    m_savePDFBtn->setIconSize(iconSz);
    m_savePDFBtn->setToolTip("Save report as PDF with circle visualization and IP pair list");
    m_sendToNtopBtn = makeActionBtn("Send to NTOP");
    m_sendToNtopBtn->setIcon(pcOutlineIcon("send", iconClr));
    m_sendToNtopBtn->setIconSize(iconSz);
    m_sendToNtopBtn->setToolTip("Upload current capture to ntopng for analysis");
    m_sendToMalcolmBtn = makeActionBtn("Send to Malcolm");
    m_sendToMalcolmBtn->setIcon(pcOutlineIcon("send", iconClr));
    m_sendToMalcolmBtn->setIconSize(iconSz);
    m_sendToMalcolmBtn->setToolTip("Upload current capture to Malcolm / Arkime for deep analysis");
    connect(m_applyFilterBtn, &QPushButton::clicked, this, &MainWindow::onApplyFilterClicked);
    connect(m_clearFilterBtn, &QPushButton::clicked, this, &MainWindow::onClearFilterClicked);
    connect(m_reloadDataBtn, &QPushButton::clicked, this, &MainWindow::onReloadDataClicked);
    connect(m_savePDFBtn, &QPushButton::clicked, this, &MainWindow::onSavePDFClicked);
    connect(m_sendToNtopBtn, &QPushButton::clicked, this, &MainWindow::onSendToNtopClicked);
    connect(m_sendToMalcolmBtn, &QPushButton::clicked, this, &MainWindow::onSendToMalcolmClicked);
    /* (ntopng right-click config removed — use ⚙ Settings instead) */

    /* Search bar — styled as a rounded search field with a leading magnifier
     * and a trailing clickable "?" help glyph (replaces the "— ? for help"
     * placeholder text). */
    m_searchLineEdit = new QLineEdit(m_controlsWidget);
    m_searchLineEdit->setObjectName("searchField");
    m_searchLineEdit->setPlaceholderText("Protocol, IP, CIDR, or port  (e.g. TCP 443)");
    m_searchLineEdit->setMinimumWidth(160);
    m_searchLineEdit->addAction(pcOutlineIcon("search", iconClr), QLineEdit::LeadingPosition);

    /* Autocomplete: all known protocol + category keywords */
    {
        static const QStringList allKeywords = {
            /* Layer-2 / MAC keywords */
            "arp", "stp", "rstp", "mstp", "pvst", "pvst+",
            "lldp", "lacp", "cdp", "vtp",
            "llc", "802.2", "eapol", "802.1x",
            "vlan", "802.1q", "mpls",
            "802.3", "ethernet",
            "macsec", "802.1ae",
            /* IP / transport */
            "icmp", "icmpv6", "tcp", "udp",
            "dhcp", "bootp", "igmp",
            "dns", "mdns",
            "gre", "ipsec", "esp", "ah",
            /* Protocol-info dialogs */
            "http", "https",
            "tls", "ssl",
            "smb", "cifs",
            "ftp",
            "ssh", "sftp", "scp",
            "telnet",
            "smtp", "email", "mail",
            "imap",
            "pop3", "pop",
            "ldap", "ldaps",
            "snmp",
            "syslog",
            "kerberos", "krb5",
            "sql", "mssql", "mysql", "postgresql", "postgres",
            "sip", "voip",
            "nbns", "nbdgm", "nbss", "netbios",
        };
        QCompleter *completer = new QCompleter(allKeywords, m_searchLineEdit);
        completer->setCaseSensitivity(Qt::CaseInsensitive);
        completer->setCompletionMode(QCompleter::PopupCompletion);
        completer->setFilterMode(Qt::MatchContains);  /* match anywhere in word */
        m_searchLineEdit->setCompleter(completer);
    }

    connect(m_searchLineEdit, &QLineEdit::returnPressed, this, [this]() {
        applySearchFilter(m_searchLineEdit->text());
    });
    connect(m_searchLineEdit, &QLineEdit::textChanged, this, [this](const QString &text) {
        if (text.trimmed().isEmpty()) {
            applySearchFilter(QString());
        }
    });

    /* Layout Row 2 — clusters separated by dividers: filter · data · integrations */
    m_controlsRow2->addWidget(m_applyFilterBtn);
    m_controlsRow2->addWidget(m_clearFilterBtn);
    m_controlsRow2->addSpacing(6);
    m_controlsRow2->addWidget(makeVDivider());
    m_controlsRow2->addSpacing(6);
    m_controlsRow2->addWidget(m_reloadDataBtn);
    m_controlsRow2->addWidget(m_savePDFBtn);
    m_controlsRow2->addSpacing(6);
    m_controlsRow2->addWidget(makeVDivider());
    m_controlsRow2->addSpacing(6);
    m_controlsRow2->addWidget(m_sendToNtopBtn);
    m_controlsRow2->addWidget(m_sendToMalcolmBtn);
    m_controlsRow2->addSpacing(12);
    m_controlsRow2->addWidget(m_searchLineEdit, 1);

    /* === Row 3: Graph-specific controls (hidden until Graph view is active) === */
    m_graphControlsRow = new QWidget(m_controlsWidget);
    QHBoxLayout *graphRow = new QHBoxLayout(m_graphControlsRow);
    graphRow->setSpacing(6);
    graphRow->setContentsMargins(0, 0, 0, 0);

    /* Helper: fuse an uppercase key label + combo into one rounded "field chip". */
    auto makeFieldChip = [this](const QString &key, QComboBox *combo) -> QWidget* {
        QFrame *chip = new QFrame(m_graphControlsRow);
        chip->setObjectName("fieldChip");
        QHBoxLayout *l = new QHBoxLayout(chip);
        l->setContentsMargins(0, 0, 0, 0);
        l->setSpacing(0);
        QLabel *k = new QLabel(key, chip);
        k->setObjectName("fieldKey");
        l->addWidget(k);
        l->addWidget(combo);   /* reparents combo into the chip */
        return chip;
    };

    /* Helper: wrap the three zoom buttons in a recessed pill (like row 1). */
    auto makeZoomPill = [this](std::initializer_list<QPushButton*> btns) -> QWidget* {
        QWidget *pill = new QWidget(m_graphControlsRow);
        pill->setObjectName("zoomPill");
        pill->setAttribute(Qt::WA_StyledBackground, true);
        QHBoxLayout *l = new QHBoxLayout(pill);
        l->setContentsMargins(3, 3, 3, 3);
        l->setSpacing(2);
        for (QPushButton *b : btns) l->addWidget(b);
        return pill;
    };

    /* Edge color */
    m_graphEdgeColorCombo  = new QComboBox(m_graphControlsRow);
    m_graphEdgeColorCombo->addItem("Protocol",      QVariant(0));
    m_graphEdgeColorCombo->addItem("TCP Window",    QVariant(6));
    m_graphEdgeColorCombo->addItem("TCP Health",    QVariant(1));
    m_graphEdgeColorCombo->addItem("Response Time", QVariant(3));
    m_graphEdgeColorCombo->addItem("Throughput",    QVariant(4));
    m_graphEdgeColorCombo->addItem("Anomaly Score", QVariant(2));
    m_graphEdgeColorCombo->addItem("High Risk",     QVariant(5));
    m_graphEdgeColorCombo->setToolTip(
        "Edge colour encoding:\n"
        "  Protocol: application protocol (same palette as circle view)\n"
        "  TCP Health: green=healthy / yellow=moderate / orange=degraded / red=unhealthy\n"
        "  Anomaly Score: green=normal / yellow=noteworthy / orange=suspicious / red=anomalous\n"
        "  Response Time: green=<5ms / yellow-green=5–50ms / yellow=50–200ms / orange=200–500ms / red=>500ms\n"
        "  Throughput: blue=<10KB/s / green=10–100KB/s / yellow=100KB–1MB/s / orange=1–10MB/s / red=>10MB/s\n"
        "  High Risk: grey=safe / yellow=elevated (SSH,SNMP) / orange=high (RDP,WinRM) / red=critical (Telnet,VNC,FTP) / purple=VPN/TOR\n"
        "  TCP Window: green=ok (>=32KB) / yellow-green=mild (8-32KB) / yellow=moderate (4-8KB) / orange=constrained (<4KB) / red=zero-window stall");

    /* Node color */
    m_graphNodeColorCombo  = new QComboBox(m_graphControlsRow);
    m_graphNodeColorCombo->addItem("Service / Port",  QVariant(0));
    m_graphNodeColorCombo->addItem("Role (Int/Ext)",  QVariant(1));
    m_graphNodeColorCombo->addItem("Protocol",        QVariant(2));
    m_graphNodeColorCombo->addItem("Function",        QVariant(3));
    m_graphNodeColorCombo->setToolTip(
        "Node colour encoding:\n"
        "  Service/Port: colour by top TCP/UDP port on this host\n"
        "  Role: Internal (blue) / External (red) / MAC (purple) / Broadcast (amber)\n"
        "  Function: Remote (crimson) / Interactive (orange) / Messaging (teal) / Filetransfer (green) / Other (grey)\n"
        "            Based on inbound destination ports — useful with Cluster layout\n"
        "  Protocol: dominant application protocol (same palette as circle view)");

    /* Layout */
    m_graphLayoutCombo  = new QComboBox(m_graphControlsRow);
    m_graphLayoutCombo->addItem("Force-directed", QVariant(0));
    m_graphLayoutCombo->addItem("Star",           QVariant(1));
    m_graphLayoutCombo->addItem("Circular",       QVariant(2));
    m_graphLayoutCombo->addItem("Grid",           QVariant(3));
    m_graphLayoutCombo->addItem("Cluster",        QVariant(4));
    m_graphLayoutCombo->addItem("Concentric",     QVariant(5));
    m_graphLayoutCombo->addItem("Hierarchical",   QVariant(6));
    m_graphLayoutCombo->addItem("Radial",         QVariant(7));
    m_graphLayoutCombo->setToolTip(
        "Initial node arrangement:\n"
        "  Force-directed: physics simulation (nodes can be dragged)\n"
        "  Star: busiest node at centre, others radially arranged\n"
        "  Circular: equal angular spacing (like circle view)\n"
        "  Grid: deterministic grid, sorted by traffic\n"
        "  Cluster: context-aware grouping — by Function category when Node=Function,\n"
        "           by network role when Node=Role, by IP subnet otherwise\n"
        "           (802.11 frame type in Wi-Fi mode)\n"
        "  Concentric: rings sorted by connection count (most-connected inner)\n"
        "  Hierarchical: tiers top-to-bottom: External / Gateway / Server / Client\n"
        "  Radial: BFS rings outward from most-connected node\n"
        "Pan: middle-mouse drag or Space+left-drag on empty space");

    /* Sync combo to GraphWidget's default (LAYOUT_STAR). Set before connecting
     * the signal so no spurious onGraphLayoutChanged fires while m_graphWidget
     * is still nullptr. */
    m_graphLayoutCombo->setCurrentIndex(GraphWidget::LAYOUT_STAR);

    /* macOS uses a native combo popup that ignores stylesheets. Force Qt's own
     * QListView so the dropdown honours the dark themed styling below. Then widen
     * the popup to fit the longest item so nothing is truncated (the closed combo
     * stays narrow inside its field chip). */
    auto styleComboPopup = [](QComboBox *c) {
        c->setView(new QListView(c));
        QFontMetrics fm(c->font());
        int w = 0;
        for (int i = 0; i < c->count(); ++i)
            w = qMax(w, fm.horizontalAdvance(c->itemText(i)));
        c->view()->setMinimumWidth(w + 44);   /* item padding + selection margins */
    };
    styleComboPopup(m_graphEdgeColorCombo);
    styleComboPopup(m_graphNodeColorCombo);
    styleComboPopup(m_graphLayoutCombo);

    QPushButton *relayoutBtn = new QPushButton("Re-layout", m_graphControlsRow);
    relayoutBtn->setObjectName("relayoutBtn");
    relayoutBtn->setIcon(pcOutlineIcon("reload", iconClr));
    relayoutBtn->setIconSize(QSize(14, 14));
    relayoutBtn->setToolTip("Re-run selected layout from scratch");

    connect(m_graphEdgeColorCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &MainWindow::onGraphEdgeColorChanged);
    connect(m_graphNodeColorCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &MainWindow::onGraphNodeColorChanged);
    connect(m_graphLayoutCombo,    QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &MainWindow::onGraphLayoutChanged);
    connect(relayoutBtn, &QPushButton::clicked, this, &MainWindow::onGraphRelayout);

    /* Zoom controls — created here so they can go straight into the pill */
    QLabel *zoomLabel = new QLabel("ZOOM", m_graphControlsRow);
    zoomLabel->setObjectName("fieldKey");
    QPushButton *zoomOutBtn   = new QPushButton("\u2212", m_graphControlsRow);  /* − */
    QPushButton *zoomResetBtn = new QPushButton("1:1",    m_graphControlsRow);
    QPushButton *zoomInBtn    = new QPushButton("+",      m_graphControlsRow);
    zoomOutBtn->setToolTip("Zoom out  (or scroll wheel down)");
    zoomInBtn->setToolTip("Zoom in  (or scroll wheel up)");
    zoomResetBtn->setToolTip("Reset zoom to 100%");
    connect(zoomOutBtn,   &QPushButton::clicked, this, [this]{ if (m_graphWidget) m_graphWidget->zoomOut(); });
    connect(zoomInBtn,    &QPushButton::clicked, this, [this]{ if (m_graphWidget) m_graphWidget->zoomIn(); });
    connect(zoomResetBtn, &QPushButton::clicked, this, [this]{ if (m_graphWidget) m_graphWidget->zoomReset(); });

    /* Layout Row 3 — field chips · divider · re-layout · divider · zoom pill */
    graphRow->addWidget(makeFieldChip("EDGE",   m_graphEdgeColorCombo));
    graphRow->addWidget(makeFieldChip("NODE",   m_graphNodeColorCombo));
    graphRow->addWidget(makeFieldChip("LAYOUT", m_graphLayoutCombo));
    graphRow->addSpacing(6);
    graphRow->addWidget(makeVDivider());
    graphRow->addSpacing(6);
    graphRow->addWidget(relayoutBtn);
    graphRow->addSpacing(6);
    graphRow->addWidget(makeVDivider());
    graphRow->addSpacing(6);
    graphRow->addWidget(zoomLabel);
    graphRow->addWidget(makeZoomPill({zoomOutBtn, zoomResetBtn, zoomInBtn}));
    graphRow->addStretch();

    m_graphControlsRow->setVisible(false);  /* hidden until Graph view is active */

    m_controlsOuterLayout->addWidget(m_row1Widget);
    m_controlsOuterLayout->addWidget(m_row2Widget);
    m_controlsOuterLayout->addWidget(m_graphControlsRow);

    m_controlsWidget->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    m_mainLayout->addWidget(m_controlsWidget);
}

void MainWindow::createCircleView()
{
    m_circleWidget = new CircleWidget(this);
    m_circleWidget->setDarkTheme(m_darkTheme);
    connect(m_circleWidget, &CircleWidget::pairSelectionChanged, 
            this, &MainWindow::onPairSelectionChanged);
    connect(m_circleWidget, &CircleWidget::nodeVisibilityToggle,
            this, &MainWindow::onNodeVisibilityToggle);
    connect(m_circleWidget, &CircleWidget::lineClicked,
            this, &MainWindow::onLineClicked);
    connect(m_circleWidget, &CircleWidget::lineHovered,
            this, &MainWindow::onLineHovered);

    m_circleContainer = new QWidget(this);
    QVBoxLayout *circleLayout = new QVBoxLayout(m_circleContainer);
    circleLayout->setContentsMargins(0, 0, 0, 0);
    circleLayout->setSpacing(0);

    circleLayout->addWidget(m_circleWidget, 1);
    /* Search bar is now in the controls toolbar */
}

void MainWindow::createTableView()
{
    m_tableWidget = new QTableWidget(this);
    m_tableWidget->setColumnCount(8);
    m_tableWidget->setHorizontalHeaderLabels(QStringList() << "" << "Source" << "Destination" 
                                                          << "Packets" << "Bytes" << "Protocol"
                                                          << "Transport" << "Top Ports");
    m_tableWidget->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_tableWidget->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_tableWidget->horizontalHeader()->setStretchLastSection(true);
    m_tableWidget->setContextMenuPolicy(Qt::CustomContextMenu);
    m_tableWidget->setMouseTracking(true);   /* needed for cellEntered */
    connect(m_tableWidget, &QTableWidget::cellEntered,
            this, [this](int row, int /*col*/) {
        QTableWidgetItem *it = m_tableWidget->item(row, 1);  /* col 1 stores pair ptr */
        if (!it) return;
        void *ptr = it->data(Qt::UserRole).value<void*>();
        onLineHovered(static_cast<comm_pair_t*>(ptr));
    });
    connect(m_tableWidget, &QTableWidget::cellClicked,
            this, &MainWindow::onTableCellClicked);
    connect(m_tableWidget, &QTableWidget::customContextMenuRequested,
            this, &MainWindow::onTableContextMenu);
    
    /* Set column widths */
    m_tableWidget->setColumnWidth(0, 30);   /* Checkbox - narrow */
    m_tableWidget->setColumnWidth(1, 140);  /* Source */
    m_tableWidget->setColumnWidth(2, 140);  /* Destination */
    m_tableWidget->setColumnWidth(3, 80);   /* Packets */
    m_tableWidget->setColumnWidth(4, 90);   /* Bytes */
    m_tableWidget->setColumnWidth(5, 90);   /* Protocol */
    m_tableWidget->setColumnWidth(6, 70);   /* Transport */
    /* Top Ports stretches to fill remaining space */

    /* Create container widget for pair list and legend */
    m_pairListContainer = new QWidget(this);
    QVBoxLayout *pairListContainerLayout = new QVBoxLayout(m_pairListContainer);
    pairListContainerLayout->setContentsMargins(0, 0, 0, 0);
    pairListContainerLayout->setSpacing(0);
    
    m_pairListWidget = new QListWidget(m_pairListContainer);
    /* Set minimum width to hold IP address pairs, but allow resizing via splitter */
    m_pairListWidget->setMinimumWidth(180);
    m_pairListWidget->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    
    /* Remove left padding/margins to minimize empty space - use stylesheet */
    /* NOTE: ANY QListWidget::item rule in a stylesheet — even one that does
     * NOT set background-color — causes Qt's stylesheet renderer to take over
     * ALL item painting, silently preventing setBackground() / setForeground()
     * calls from having any visible effect.  This breaks the search-result
     * red-blink animation.  Therefore we ONLY style the container (padding,
     * border) and handle per-item sizing via setSizeHint() when items are
     * created.                                                                */
    m_pairListWidget->setStyleSheet(
        "QListWidget { "
        "    padding: 0px; "
        "    margin: 0px; "
        "    border: none; "
        "} "
    );
    
    /* Set fixed-width font for IP list - use platform-appropriate size */
#ifdef Q_OS_WIN
    QFont fixedFont("Consolas", 11);
#else
    QFont fixedFont("Courier", 15);
#endif
    m_pairListWidget->setFont(fixedFont);

    /* Ensure items have proper spacing */
    m_pairListWidget->setSpacing(0);
    
    /* Set uniform item sizes for consistent display */
    m_pairListWidget->setUniformItemSizes(true);
    
    /* Connect item changed signal to update circle widget selections */
    connect(m_pairListWidget, &QListWidget::itemChanged, this, &MainWindow::onPairListItemChanged);

    /* Right-click context menu for selection operations */
    m_pairListWidget->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(m_pairListWidget, &QListWidget::customContextMenuRequested,
            this, &MainWindow::onPairListContextMenu);

    /* Event filter for direction-arrow toggling: clicking a row (non-checkbox area)
     * on a bidirectional item cycles the arrow between --> <-> <-- */
    m_pairListWidget->viewport()->installEventFilter(this);

    /* Add pair list to container - it will expand */
    pairListContainerLayout->addWidget(m_pairListWidget, 1);  /* Stretch factor 1 = takes available space */
    
    /* Create and add legend widget to bottom of pair list container */
    createLegend();
    pairListContainerLayout->addWidget(m_legendWidget, 0);  /* Stretch factor 0 = fixed size */
    
    /* Set container size policy - allow resizing via splitter, with reasonable minimum */
    m_pairListContainer->setMinimumWidth(180);
    m_pairListContainer->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Expanding);
}

void MainWindow::createLegend()
{
    /* Create legend widget as child of pair list container */
    m_legendWidget = new QWidget(m_pairListContainer);
    QVBoxLayout *outerLayout = new QVBoxLayout(m_legendWidget);
    outerLayout->setContentsMargins(5, 5, 5, 5);
    outerLayout->setSpacing(3);  /* Small spacing between rows */
    
    /* Create two horizontal rows */
    m_legendLayout = new QHBoxLayout();
    m_legendLayout->setContentsMargins(0, 0, 0, 0);
    m_legendLayout->setSpacing(8);  /* Spacing between category groups */

    m_legendRow2Layout = new QHBoxLayout();
    m_legendRow2Layout->setContentsMargins(0, 0, 0, 0);
    m_legendRow2Layout->setSpacing(8);  /* Spacing between category groups */

    outerLayout->addLayout(m_legendLayout);
    outerLayout->addLayout(m_legendRow2Layout);

    /* Set compact fixed height for legend - two rows */
    m_legendWidget->setMinimumHeight(65);
    m_legendWidget->setMaximumHeight(65);
    /* Span the width of the IP pair window */
    m_legendWidget->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
}

void MainWindow::updateViews()
{
    static bool updating = false;
    if (updating) {
        /* Prevent recursive calls */
        return;
    }
    updating = true;
    
    if (!m_analysisResult) {
        if (m_circleWidget) m_circleWidget->setPairs(NULL, NULL);
        if (m_graphWidget)  m_graphWidget->setPairs(NULL, NULL);
        if (m_circle_pairs) {
            g_list_free(m_circle_pairs);
            m_circle_pairs = NULL;
        }
        m_tableWidget->setRowCount(0);
        m_pairListWidget->clear();
        updating = false;
        return;
    }

    if (!m_analysisResult->pairs) {
        if (m_circleWidget) m_circleWidget->setPairs(NULL, NULL);
        if (m_graphWidget)  m_graphWidget->setPairs(NULL, NULL);
        if (m_circle_pairs) {
            g_list_free(m_circle_pairs);
            m_circle_pairs = NULL;
        }
        m_tableWidget->setRowCount(0);
        m_pairListWidget->clear();
        updating = false;
        return;
    }

    /* Clear widget references to old pairs first */
    if (m_circleWidget) m_circleWidget->setPairs(NULL, NULL);
    if (m_graphWidget)  m_graphWidget->setPairs(NULL, NULL);

    /* Free old circle_pairs list if it exists (only list nodes, pairs are owned by m_analysisResult) */
    if (m_circle_pairs) {
        g_list_free(m_circle_pairs);
        m_circle_pairs = NULL;
    }
    
    /* Don't free m_top_pairs - it contains pointers to pairs owned by m_analysisResult */
    /* The list nodes are small and will be cleaned up when m_analysisResult is freed */
    /* Setting to NULL prevents use-after-free issues */
    m_top_pairs = NULL;

    /* Number of pairs to show — 25 cap in search override mode */
    guint display_limit = m_searchOverrideMode ? 25u : m_topN;

    /* Get top pairs - we'll show both directions, so get enough pairs */
    if (m_searchOverrideMode && m_searchOverridePairs) {
        /* Override mode: display full-buffer search results instead of Top-N ranked pairs.
         * m_searchOverridePairs is borrowed from m_analysisResult — do not free it here. */
        m_top_pairs = m_searchOverridePairs;
    } else {
        m_top_pairs = packet_analyzer_get_top_pairs(m_analysisResult, m_topN, m_useBytes);
    }
    if (!m_top_pairs) {
        /* No pairs to display */
        if (m_circleWidget) {
            m_circleWidget->setPairs(NULL, NULL);
        }
        if (m_circle_pairs) {
            g_list_free(m_circle_pairs);
            m_circle_pairs = NULL;
        }
        m_tableWidget->setRowCount(0);
        m_pairListWidget->clear();
        updating = false;
        return;
    }

    /* Update circle view - limit to exactly top_n pairs for the circle */
    if (m_circleWidget) {
        /* Free old circle_pairs list if it exists (only list nodes, pairs are owned by m_analysisResult) */
        if (m_circle_pairs) {
            g_list_free(m_circle_pairs);
            m_circle_pairs = NULL;
        }
        
        /* Create a limited list with exactly display_limit pairs for the circle widget */
        GList *iter;
        guint pair_count = 0;
        for (iter = m_top_pairs; iter && pair_count < display_limit; iter = iter->next, pair_count++) {
            m_circle_pairs = g_list_append(m_circle_pairs, iter->data);
        }

        m_circleWidget->setMaxPairs(display_limit);
        m_circleWidget->setUseBytes(m_useBytes);
        m_circleWidget->setPairs(m_circle_pairs, m_analysisResult->protocols);
        m_circleWidget->setSelectedPairs(m_selectedPairs);
        
        /* Note: m_circle_pairs list nodes will be freed in destructor or when updateViews is called again */
        /* The pairs themselves are owned by m_analysisResult, so we don't free them */
    }

    /* Update graph view — uses the same m_circle_pairs list as circle view */
    if (m_graphWidget) {
        m_graphWidget->setMaxPairs(display_limit);
        m_graphWidget->setUseBytes(m_useBytes);
        m_graphWidget->setShowLineThickness(m_lineThicknessCheckBox
                                            ? (gboolean)m_lineThicknessCheckBox->isChecked()
                                            : FALSE);
        /* Apply active threshold group */
        if (m_activeThresholdGroup >= 0 && m_activeThresholdGroup < m_thresholdGroups.size())
            m_graphWidget->setThresholds(m_thresholdGroups[m_activeThresholdGroup]);
        m_graphWidget->setPairs(m_circle_pairs, m_analysisResult->protocols);
        m_graphWidget->setSelectedPairs(m_selectedPairs);
    }

    /* Update table view — adjust columns for Wi-Fi vs standard mode */
    m_tableWidget->setRowCount(0);
    m_tableCheckboxes.clear();

    if (m_wifiMode) {
        m_tableWidget->setColumnCount(9);
        m_tableWidget->setHorizontalHeaderLabels(QStringList()
            << "" << "Station" << "BSSID" << "SSID" << "Ch"
            << "Signal" << "Frames" << "Bytes" << "Retries");
        m_tableWidget->setColumnWidth(0, 30);
        m_tableWidget->setColumnWidth(1, 140);
        m_tableWidget->setColumnWidth(2, 140);
        m_tableWidget->setColumnWidth(3, 110);
        m_tableWidget->setColumnWidth(4, 40);
        m_tableWidget->setColumnWidth(5, 110);
        m_tableWidget->setColumnWidth(6, 70);
        m_tableWidget->setColumnWidth(7, 80);
        /* Retries stretches */
    } else {
        m_tableWidget->setColumnCount(8);
        m_tableWidget->setHorizontalHeaderLabels(QStringList()
            << "" << "Source" << "Destination" << "Packets" << "Bytes"
            << "Protocol" << "Transport" << "Top Ports");
        m_tableWidget->setColumnWidth(0, 30);
        m_tableWidget->setColumnWidth(1, 140);
        m_tableWidget->setColumnWidth(2, 140);
        m_tableWidget->setColumnWidth(3, 80);
        m_tableWidget->setColumnWidth(4, 90);
        m_tableWidget->setColumnWidth(5, 90);
        m_tableWidget->setColumnWidth(6, 70);
        /* Top Ports stretches */
    }

    GList *iter;
    guint row = 0;
    for (iter = m_top_pairs; iter; iter = iter->next, row++) {
        comm_pair_t *pair = (comm_pair_t *)iter->data;
        if (!pair || !pair->src_addr || !pair->dst_addr)
            continue;
            
        m_tableWidget->insertRow(row);

        /* Checkbox centered in cell */
        QCheckBox *checkbox = new QCheckBox();
        checkbox->setChecked(true);
        QWidget *checkWidget = new QWidget();
        QHBoxLayout *checkLayout = new QHBoxLayout(checkWidget);
        checkLayout->addWidget(checkbox);
        checkLayout->setAlignment(Qt::AlignCenter);
        checkLayout->setContentsMargins(0, 0, 0, 0);
        m_tableWidget->setCellWidget(row, 0, checkWidget);
        m_tableCheckboxes[checkbox] = pair;
        connect(checkbox, &QCheckBox::toggled, this, [this, pair](bool checked) {
            onTableCheckboxToggled(pair, checked);
        });

        if (m_wifiMode) {
            /* ---- Wi-Fi table row ---- */
            QString station = pair->resolved_src ? QString::fromUtf8(pair->resolved_src) : QString::fromUtf8(pair->src_addr);
            QString bssid   = pair->wifi_bssid   ? QString::fromUtf8(pair->wifi_bssid)   : QString::fromUtf8(pair->dst_addr);
            QTableWidgetItem *stItem = new QTableWidgetItem(station);
            stItem->setData(Qt::UserRole, QVariant::fromValue<void*>(pair));
            m_tableWidget->setItem(row, 1, stItem);
            m_tableWidget->setItem(row, 2, new QTableWidgetItem(bssid));

            /* SSID */
            m_tableWidget->setItem(row, 3, new QTableWidgetItem(
                pair->wifi_ssid ? QString::fromUtf8(pair->wifi_ssid) : ""));

            /* Channel */
            QTableWidgetItem *chItem = new QTableWidgetItem(
                pair->wifi_channel > 0 ? QString::number(pair->wifi_channel) : "-");
            chItem->setTextAlignment(Qt::AlignCenter);
            m_tableWidget->setItem(row, 4, chItem);

            /* Signal: quality label + avg dBm */
            QString sigText = "-";
            if (pair->rssi_count > 0) {
                int avg = (int)(pair->rssi_sum / (gint32)pair->rssi_count);
                QString quality;
                const auto &wt = m_wifiThresholdGroups[m_activeWifiThresholdGroup];
                if (avg >= wt.rssi_excellent)      quality = "Excellent";
                else if (avg >= wt.rssi_good)      quality = "Good";
                else if (avg >= wt.rssi_fair)      quality = "Fair";
                else                               quality = "Poor";
                sigText = QString("%1 (%2 dBm)").arg(quality).arg(avg);
            }
            m_tableWidget->setItem(row, 5, new QTableWidgetItem(sigText));

            /* Frames */
            QTableWidgetItem *frmItem = new QTableWidgetItem(QString::number(pair->packet_count));
            frmItem->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
            m_tableWidget->setItem(row, 6, frmItem);

            /* Bytes */
            QString bytesStr;
            if (pair->byte_count >= 1048576)
                bytesStr = QString("%1 MB").arg(pair->byte_count / 1048576.0, 0, 'f', 1);
            else if (pair->byte_count >= 1024)
                bytesStr = QString("%1 KB").arg(pair->byte_count / 1024.0, 0, 'f', 1);
            else
                bytesStr = QString("%1 B").arg(pair->byte_count);
            QTableWidgetItem *byteItem = new QTableWidgetItem(bytesStr);
            byteItem->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
            m_tableWidget->setItem(row, 7, byteItem);

            /* Retries: count (pct%) */
            QString retryStr = "-";
            if (pair->retry_count > 0 && pair->packet_count > 0) {
                double pct = 100.0 * pair->retry_count / pair->packet_count;
                retryStr = QString("%1 (%2%)").arg(pair->retry_count).arg(QString::number(pct, 'f', 1));
            }
            QTableWidgetItem *retryItem = new QTableWidgetItem(retryStr);
            retryItem->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
            m_tableWidget->setItem(row, 8, retryItem);
        } else {
            /* ---- Standard table row ---- */
            QString displaySrc = pair->resolved_src ? QString::fromUtf8(pair->resolved_src) : QString::fromUtf8(pair->src_addr);
            QString displayDst = pair->resolved_dst ? QString::fromUtf8(pair->resolved_dst) : QString::fromUtf8(pair->dst_addr);
            QTableWidgetItem *srcItem = new QTableWidgetItem(displaySrc);
            srcItem->setData(Qt::UserRole, QVariant::fromValue<void*>(pair));
            m_tableWidget->setItem(row, 1, srcItem);
            m_tableWidget->setItem(row, 2, new QTableWidgetItem(displayDst));

            QTableWidgetItem *pktItem = new QTableWidgetItem(QString::number(pair->packet_count));
            pktItem->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
            m_tableWidget->setItem(row, 3, pktItem);

            QTableWidgetItem *byteItem = new QTableWidgetItem(QString::number(pair->byte_count));
            byteItem->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
            m_tableWidget->setItem(row, 4, byteItem);

            m_tableWidget->setItem(row, 5, new QTableWidgetItem(pair->top_protocol ? pair->top_protocol : "Unknown"));

            QString transport;
            if (pair->has_tcp && pair->has_udp) transport = "TCP+UDP";
            else if (pair->has_tcp) transport = "TCP";
            else if (pair->has_udp) transport = "UDP";
            else transport = "-";
            m_tableWidget->setItem(row, 6, new QTableWidgetItem(transport));

            /* Top Ports column */
            QString portsStr;
            if (pair->dst_ports) {
                QList<QPair<guint16, guint64>> port_list;
                GHashTableIter port_iter;
                gpointer port_key, port_value;
                g_hash_table_iter_init(&port_iter, pair->dst_ports);
                while (g_hash_table_iter_next(&port_iter, &port_key, &port_value)) {
                    guint16 port = GPOINTER_TO_UINT(port_key);
                    port_stats_t *ps = (port_stats_t *)port_value;
                    guint64 count = ps ? ps->count : 0;
                    port_list.append(qMakePair(port, count));
                }
                std::sort(port_list.begin(), port_list.end(),
                          [](const QPair<guint16, guint64> &a, const QPair<guint16, guint64> &b) {
                              return a.second > b.second;
                          });
                QStringList port_strs;
                int shown = 0;
                for (const auto &p : port_list) {
                    if (shown >= 3) break;
                    QString name;
                    switch (p.first) {
                        case 80: name = "HTTP"; break;
                        case 443: name = "HTTPS"; break;
                        case 53: name = "DNS"; break;
                        case 22: name = "SSH"; break;
                        case 445: name = "SMB"; break;
                        case 3389: name = "RDP"; break;
                        case 1433: name = "MSSQL"; break;
                        case 3306: name = "MySQL"; break;
                        case 21: name = "FTP"; break;
                        case 25: name = "SMTP"; break;
                        case 110: name = "POP3"; break;
                        case 143: name = "IMAP"; break;
                        case 8080: name = "HTTP-Alt"; break;
                        case 5060: name = "SIP"; break;
                        case 5061: name = "SIPS"; break;
                        case 123: name = "NTP"; break;
                        case 161: name = "SNMP"; break;
                        case 389: name = "LDAP"; break;
                        case 636: name = "LDAPS"; break;
                        case 88: name = "Kerberos"; break;
                        default: name = QString::number(p.first); break;
                    }
                    if (name != QString::number(p.first))
                        port_strs << QString("%1/%2").arg(name).arg(p.first);
                    else
                        port_strs << name;
                    shown++;
                }
                portsStr = port_strs.join(", ");
            }
            m_tableWidget->setItem(row, 7, new QTableWidgetItem(portsStr));
        }
    }

    /* Update pair list */
    m_pairListWidget->clear();
    m_linkedPairs.clear();  /* No longer populated &mdash; single row per group */
    
    /* Build a map to group bidirectional pairs together */
    QMap<QString, QList<comm_pair_t*>> pair_groups;  /* Key: sorted address pair, Value: list of pairs */
    
    /* First pass: group pairs by their addresses (sorted) to find bidirectional pairs */
    for (iter = m_top_pairs; iter; iter = iter->next) {
        comm_pair_t *pair = (comm_pair_t *)iter->data;
        if (!pair || !pair->src_addr || !pair->dst_addr)
            continue;
        
        QString addr1 = QString::fromUtf8(pair->src_addr);
        QString addr2 = QString::fromUtf8(pair->dst_addr);
        
        /* Create a canonical key by sorting addresses to group bidirectional pairs */
        QString key = (addr1 < addr2) ? QString("%1|%2").arg(addr1).arg(addr2) 
                                      : QString("%1|%2").arg(addr2).arg(addr1);
        
        if (!pair_groups.contains(key)) {
            pair_groups[key] = QList<comm_pair_t*>();
        }
        pair_groups[key].append(pair);
    }
    
    /* Find maximum display address length for alignment (use resolved names if available) */
    guint max_src_len = 0;
    guint max_dst_len = 0;
    for (iter = m_top_pairs; iter; iter = iter->next) {
        comm_pair_t *pair = (comm_pair_t *)iter->data;
        if (!pair || !pair->src_addr || !pair->dst_addr)
            continue;
        QString dSrc = pair->resolved_src ? QString::fromUtf8(pair->resolved_src) : QString::fromUtf8(pair->src_addr);
        QString dDst = pair->resolved_dst ? QString::fromUtf8(pair->resolved_dst) : QString::fromUtf8(pair->dst_addr);
        guint src_len = (guint)dSrc.length();
        guint dst_len = (guint)dDst.length();
        if (src_len > max_src_len)
            max_src_len = src_len;
        if (dst_len > max_dst_len)
            max_dst_len = dst_len;
    }
    
    /* Second pass: create list items, keeping bidirectional pairs adjacent and linking checkboxes */
    guint list_entry_count = 0;
#ifdef Q_OS_WIN
    QFont fixedFont("Consolas", 11);
#else
    QFont fixedFont("Courier", 15);
#endif
    
    for (auto group_it = pair_groups.begin(); group_it != pair_groups.end() && list_entry_count < display_limit; ++group_it) {
        QList<comm_pair_t*> &pairs = group_it.value();

        /* Sort pairs within group: A→B before B→A (alphabetically) */
        std::sort(pairs.begin(), pairs.end(), [](comm_pair_t *a, comm_pair_t *b) {
            QString a_src = QString::fromUtf8(a->src_addr);
            QString a_dst = QString::fromUtf8(a->dst_addr);
            QString b_src = QString::fromUtf8(b->src_addr);
            QString b_dst = QString::fromUtf8(b->dst_addr);
            if (a_src != b_src)
                return a_src < b_src;
            return a_dst < b_dst;
        });

        /* One row per group:
         *   Qt::UserRole   — primary pair  (A→B)
         *   Qt::UserRole+1 — secondary pair (B→A), nullptr for unidirectional
         *   Qt::UserRole+2 — direction state: 0=→ forward, 1=↔ both, 2=← reverse */
        comm_pair_t *primary   = pairs[0];
        comm_pair_t *secondary = (pairs.size() >= 2) ? pairs[1] : nullptr;
        int dir = secondary ? 1 : 0;  /* default: &#x2194; for bidirectional, &rarr; for unidirectional */

        /* Display text is always based on primary pair's addresses */
        QString src_addr = primary->resolved_src ? QString::fromUtf8(primary->resolved_src)
                                                 : QString::fromUtf8(primary->src_addr);
        QString dst_addr = primary->resolved_dst ? QString::fromUtf8(primary->resolved_dst)
                                                 : QString::fromUtf8(primary->dst_addr);

        /* Truncate long addresses/names — will be refined by refreshPairListText() */
        if (!m_wifiMode) {
            src_addr = truncateIPv6Address(src_addr);
            dst_addr = truncateIPv6Address(dst_addr);
        }

        /* Pad for alignment */
        src_addr = src_addr.leftJustified(max_src_len, ' ');
        dst_addr = dst_addr.leftJustified(max_dst_len, ' ');

        /* ASCII arrows: consistent advance-width in any monospace font on all platforms.
         * Unicode ⇒/⇔/⇐ render at inconsistent widths in Consolas on Windows. */
        const char *arrow = (dir == 1) ? " <-> "
                          : (dir == 2) ? " <-- "
                          :              " --> ";

        QString text = src_addr + QString::fromUtf8(arrow) + dst_addr;
        QListWidgetItem *item = new QListWidgetItem(m_pairListWidget);
        item->setFlags(item->flags() | Qt::ItemIsUserCheckable);
        item->setCheckState(Qt::Checked);
        item->setData(Qt::UserRole,     QVariant::fromValue((void*)primary));
        item->setData(Qt::UserRole + 1, QVariant::fromValue((void*)secondary));
        item->setData(Qt::UserRole + 2, dir);
        item->setSizeHint(QSize(-1, 30));
        item->setFont(fixedFont);
        item->setText(text);

        m_pairListWidget->addItem(item);
        list_entry_count++;
    }
    
    /* Initialize visible pairs after creating list items */
    updateVisiblePairsFromWidgets();

    /* Adapt display names to available width (truncate long hostnames etc.) */
    refreshPairListText();

    /* Auto-fit pair list width to content on first data load (when no saved
     * splitter position exists).  Measures the widest item text plus checkbox
     * and scrollbar overhead, then sizes the splitter so the pair list is
     * just wide enough to show everything without wasted space.             */
    if (!m_splitterSizesRestored && m_splitter && m_pairListWidget->count() > 0) {
        QFontMetrics fm(m_pairListWidget->font());
        int maxTextWidth = 0;
        for (int i = 0; i < m_pairListWidget->count(); i++) {
            QListWidgetItem *item = m_pairListWidget->item(i);
            if (!item) continue;
            int w = fm.horizontalAdvance(item->text());
            if (w > maxTextWidth) maxTextWidth = w;
        }
        /* Add space for: checkbox (~28px) + left padding + scrollbar (~18px) + margin */
        int idealWidth = maxTextWidth + 60;
        int minWidth = 180;
        int maxWidth = m_splitter->width() / 2;  /* never more than half */
        idealWidth = qBound(minWidth, idealWidth, maxWidth);

        int totalWidth = m_splitter->width();
        if (totalWidth > 0) {
            m_splitter->setSizes(QList<int>() << (totalWidth - idealWidth) << idealWidth);
        }
    }

    /* Re-apply search highlights if query is present */
    if (m_searchLineEdit && !m_searchLineEdit->text().trimmed().isEmpty()) {
        applySearchFilter(m_searchLineEdit->text());
    }
    
    /* Note: m_top_pairs contains pointers to pairs owned by m_analysisResult */
    /* We free m_top_pairs (the list structure) but not the pairs themselves */
    
    updating = false;
}

void MainWindow::updateLegend()
{
    /* Clear existing legend items and checkboxes from both rows */
    QLayoutItem *item;
    while ((item = m_legendLayout->takeAt(0)) != NULL) {
        if (item->widget()) delete item->widget();
        delete item;
    }
    while ((item = m_legendRow2Layout->takeAt(0)) != NULL) {
        if (item->widget()) delete item->widget();
        delete item;
    }

    /* Clear checkbox hash */
    m_protocolCheckboxes.clear();

    /* Wi-Fi mode: show 4-bin RSSI legend instead of protocol categories */
    if (m_wifiMode) {
        const auto &wt = m_wifiThresholdGroups[m_activeWifiThresholdGroup];
        struct RssiLegendItem {
            QString label;
            QString range;
            int r, g, b;         /* swatch color (on-screen palette to match CircleWidget) */
        };
        const RssiLegendItem bins[] = {
            {"Excellent", QString(">= %1 dBm").arg(wt.rssi_excellent),                                   0, 200,  0},
            {"Good",      QString("%1..%2 dBm").arg(wt.rssi_good).arg(wt.rssi_excellent - 1),          160, 220,  0},
            {"Fair",      QString("%1..%2 dBm").arg(wt.rssi_fair).arg(wt.rssi_good - 1),               255, 165,  0},
            {"Poor",      QString("< %1 dBm").arg(wt.rssi_fair),                                        220,  30, 30}
        };

        QString borderColor = m_darkTheme ? "#666" : "#aaa";
        for (int i = 0; i < 4; i++) {
            const RssiLegendItem &it = bins[i];
            /* Color swatch */
            QLabel *color_label = new QLabel(m_legendWidget);
            color_label->setStyleSheet(QString("background-color: rgb(%1,%2,%3); min-width: 12px; min-height: 12px; max-width: 12px; max-height: 12px; border: 1px solid %4;")
                                       .arg(it.r).arg(it.g).arg(it.b).arg(borderColor));
            color_label->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);

            /* Text label */
            QLabel *text_label = new QLabel(QString("%1 (%2)").arg(it.label).arg(it.range), m_legendWidget);
            text_label->setSizePolicy(QSizePolicy::Minimum, QSizePolicy::Fixed);
            text_label->setStyleSheet("QLabel { font-size: 9pt; }");

            /* Distribute 2 per row for balance */
            QHBoxLayout *targetLayout = (i < 2) ? m_legendLayout : m_legendRow2Layout;
            targetLayout->addWidget(color_label);
            targetLayout->addWidget(text_label);
        }
        qDebug() << "updateLegend: Wi-Fi mode — added 4-bin RSSI legend";
        return;
    }

    /* Define protocol categories */
    struct ProtocolCategory {
        QString name;
        QStringList protocols;  /* Protocols that belong to this category */
        guint32 color;
    };
    
    ProtocolCategory categories[] = {
        {"ARP",            QStringList() << "ARP" << "RARP", 0x87CEEB},  /* Sky Blue */
        {"ICMP",           QStringList() << "ICMP" << "ICMPv6", 0xAFEEEE},  /* Pale Turquoise */
        {"TCP",            QStringList() << "TCP", 0x90EE90},  /* Light Green */
        {"UDP",            QStringList() << "UDP", 0xFFB347},  /* Pastel Orange */
        {"Infrastructure", QStringList() << "OSPF" << "BGP" << "RIP" << "RIPv2" << "EIGRP"
                                         << "ISIS" << "IS-IS" << "IGMP" << "IGMPv2" << "IGMPv3"
                                         << "PIM" << "VRRP" << "HSRP" << "SCTP" << "DCCP"
                                         /* Bridge / switching infrastructure */
                                         << "STP" << "RSTP" << "MSTP" << "PVST" << "PVST+"
                                         << "LLDP" << "LACP" << "CDP" << "VTP" << "MPLS", 0xFFE4B5},  /* Moccasin */
        {"Unknown",        QStringList() << "Unknown" << "IP" << "IPv4" << "IPv6" << "Ethernet", 0x808080}  /* Gray */
    };
    const int NUM_CATEGORIES = 6;
    
    /* Build set of protocols found in analysis */
    QSet<QString> found_protocols;
    if (m_analysisResult && m_analysisResult->protocols) {
        GHashTableIter iter;
        gpointer key, value;
        g_hash_table_iter_init(&iter, m_analysisResult->protocols);
        while (g_hash_table_iter_next(&iter, &key, &value)) {
            protocol_stats_t *stats = (protocol_stats_t *)value;
            if (stats && stats->protocol_name && *stats->protocol_name) {
                QString protocol_name = QString::fromUtf8(stats->protocol_name);
                if (protocol_name.contains("Missing", Qt::CaseInsensitive)) {
                    protocol_name = "Unknown";
                }
                found_protocols.insert(protocol_name);
            }
        }
    }
    
    /* Add category groups to legend - split into three rows */
    for (int i = 0; i < NUM_CATEGORIES; i++) {
        ProtocolCategory &cat = categories[i];

        /* Check if any protocol in this category was found in the FULL trace */
        bool category_found = false;
        for (const QString &proto : cat.protocols) {
            if (found_protocols.contains(proto)) {
                category_found = true;
                break;
            }
        }

        /* Check if any protocol in this category is in the CURRENT TOP-N list */
        bool category_in_topn = false;
        for (GList *it = m_top_pairs; it && !category_in_topn; it = it->next) {
            comm_pair_t *p = (comm_pair_t*)it->data;
            if (!p) continue;
            if (p->top_protocol) {
                QString proto = QString::fromUtf8(p->top_protocol);
                for (const QString &cp : cat.protocols) {
                    if (proto.compare(cp, Qt::CaseInsensitive) == 0) {
                        category_in_topn = true;
                        break;
                    }
                }
            }
            if (!category_in_topn && p->has_tcp && cat.protocols.contains("TCP"))
                category_in_topn = true;
            if (!category_in_topn && p->has_udp && cat.protocols.contains("UDP"))
                category_in_topn = true;
        }

        /* Fallback: if top-N didn't cover this category but it IS in the trace,
         * scan ALL pairs — catches L2/broadcast protocols (ARP, STP, …) that rank
         * below the top-N cut-off by byte count yet are genuinely present. */
        if (!category_in_topn && category_found && m_analysisResult) {
            for (GList *it = m_analysisResult->pairs; it && !category_in_topn; it = it->next) {
                comm_pair_t *fp = (comm_pair_t*)it->data;
                if (!fp) continue;
                if (fp->top_protocol) {
                    QString proto = QString::fromUtf8(fp->top_protocol);
                    for (const QString &cp : cat.protocols) {
                        if (proto.compare(cp, Qt::CaseInsensitive) == 0) {
                            category_in_topn = true;
                            break;
                        }
                    }
                }
                if (!category_in_topn && fp->has_tcp && cat.protocols.contains("TCP"))
                    category_in_topn = true;
                if (!category_in_topn && fp->has_udp && cat.protocols.contains("UDP"))
                    category_in_topn = true;
            }
        }

        /* Get representative color for category */
        QColor color((cat.color >> 16) & 0xFF, (cat.color >> 8) & 0xFF, cat.color & 0xFF);

        /* Create color box */
        QLabel *color_label = new QLabel(m_legendWidget);
        QString borderColor = m_darkTheme ? "#666" : "#aaa";
        color_label->setStyleSheet(QString("background-color: rgb(%1,%2,%3); min-width: 12px; min-height: 12px; max-width: 12px; max-height: 12px; border: 1px solid %4;")
                                   .arg(color.red()).arg(color.green()).arg(color.blue()).arg(borderColor));
        color_label->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);

        /* Create checkbox for category */
        QCheckBox *category_checkbox = new QCheckBox(cat.name, m_legendWidget);

        if (category_found && category_in_topn) {
            /* STATE 1: Category present in top-N — normal enabled checkbox */
            category_checkbox->setChecked(true);
            category_checkbox->setEnabled(true);
            if (m_darkTheme)
                category_checkbox->setStyleSheet("QCheckBox { font-size: 9pt; }");
            else
                category_checkbox->setStyleSheet("QCheckBox { font-size: 9pt; }");
            /* Connect to normal toggle filter */
            connect(category_checkbox, &QCheckBox::toggled, this, [this, cat](bool checked) {
                onProtocolCategoryToggled(cat.name, cat.protocols, checked);
            });

        } else {
            /* Category not represented in the current top-N — show as disabled dash */
            category_checkbox->setTristate(true);
            category_checkbox->setCheckState(Qt::PartiallyChecked);
            category_checkbox->setEnabled(false);
            if (m_darkTheme)
                category_checkbox->setStyleSheet(
                    "QCheckBox { font-size: 9pt; } QCheckBox:disabled { color: #888; }");
            else
                category_checkbox->setStyleSheet(
                    "QCheckBox { font-size: 9pt; } QCheckBox:disabled { color: #aaa; }");
        }

        category_checkbox->setSizePolicy(QSizePolicy::Minimum, QSizePolicy::Fixed);

        /* Store checkbox in hash using category name */
        m_protocolCheckboxes[cat.name] = category_checkbox;

        /* Add to appropriate row: first 3 in row 1, last 3 in row 2 */
        QHBoxLayout *targetLayout;
        if (i < 3)  targetLayout = m_legendLayout;
        else        targetLayout = m_legendRow2Layout;
        targetLayout->addWidget(color_label);
        targetLayout->addWidget(category_checkbox);
    }

    qDebug() << "updateLegend: Added" << NUM_CATEGORIES << "protocol categories to legend";
}

void MainWindow::updateAnalysis(analysis_result_t *result)
{
    /* Log what we received */
    if (result) {
        guint pairs_count = result->pairs ? g_list_length(result->pairs) : 0;
        qDebug() << "MainWindow::updateAnalysis: received" << pairs_count << "pairs";
        qDebug() << "MainWindow::updateAnalysis: total_packets=" << result->total_packets 
                 << "total_bytes=" << result->total_bytes;
    } else {
        qDebug() << "MainWindow::updateAnalysis: received NULL result";
    }
    
    /* Exit search override mode — override pairs point into the OLD m_analysisResult */
    if (m_searchOverrideMode) {
        m_searchOverrideMode = false;
        m_searchOverridePairs = NULL;  /* will be invalid once old result is freed */
        (void)0; /* search override cleared */
        /* Restore Top-N buttons silently */
        QButtonGroup *grp = m_top10Btn ? m_top10Btn->group() : nullptr;
        if (grp) grp->setExclusive(false);
        if (m_top10Btn) m_top10Btn->setChecked(m_savedTopN == 10);
        if (m_top25Btn) m_top25Btn->setChecked(m_savedTopN == 25);
        if (m_top50Btn) m_top50Btn->setChecked(m_savedTopN == 50);
        if (grp) grp->setExclusive(true);
        m_topN = m_savedTopN;
    }

    /* Clear CircleWidget's pairs and free top_pairs BEFORE freeing old result */
    if (m_circleWidget) {
        m_circleWidget->setPairs(NULL, NULL);
    }

    /* Clear CircleWidget's reference to old pairs first */
    if (m_circleWidget) {
        m_circleWidget->setPairs(NULL, NULL);
    }

    /* Don't free m_top_pairs - it contains pointers to pairs owned by m_analysisResult */
    /* Setting to NULL prevents use-after-free issues */
    m_top_pairs = NULL;

    /* Tier 3: invalidate analysis cache — pairs and capture data are about to change */
    s_analysisCache.clear();

    if (m_analysisResult) {
        packet_analyzer_free_result(m_analysisResult);
    }
    m_analysisResult = result;

    /* Detect Wi-Fi mode from analysis result and adapt UI */
    bool wasWifi = m_wifiMode;
    m_wifiMode = (result && result->mode == ANALYSIS_MODE_WIFI);
    if (m_circleWidget) {
        m_circleWidget->setWiFiMode(m_wifiMode);
        if (m_wifiMode)
            m_circleWidget->setWifiThresholds(m_wifiThresholdGroups[m_activeWifiThresholdGroup]);
    }
    if (m_graphWidget) {
        m_graphWidget->setWiFiMode(m_wifiMode);
    }
    /* Hide IP/MAC toggle in Wi-Fi mode (always uses MAC internally) */
    if (m_ipBtn)  m_ipBtn->setVisible(!m_wifiMode);
    if (m_macBtn) m_macBtn->setVisible(!m_wifiMode);
    /* In WiFi mode: hide protocol-based edge/node color combos in the graph
     * controls row — signal quality is always used instead.             */
    if (m_graphEdgeColorCombo) m_graphEdgeColorCombo->setVisible(!m_wifiMode);
    if (m_graphNodeColorCombo) m_graphNodeColorCombo->setVisible(!m_wifiMode);
    /* Hide the Edge:/Node: labels that sit next to the combos */
    if (m_graphControlsRow) {
        const QList<QObject*> children = m_graphControlsRow->children();
        int labelIdx = 0;
        for (QObject *child : children) {
            QLabel *lbl = qobject_cast<QLabel*>(child);
            if (lbl && (lbl->text() == "Edge:" || lbl->text() == "Node:"))
                lbl->setVisible(!m_wifiMode);
        }
        Q_UNUSED(labelIdx);
    }

    /* WAN encapsulation advisory: show once when a non-Ethernet capture is detected.
     * PacketCircle automatically switches to IP mode for these capture types.       */
    if (result && result->encap_name) {
        /* Force the UI toggle to IP mode so it stays consistent */
        m_useMAC = FALSE;
        if (m_ipBtn)  m_ipBtn->setChecked(true);
        if (m_macBtn) m_macBtn->setChecked(false);
        QMessageBox::information(
            this,
            QString("Special Encapsulation Detected"),
            QString("<b>%1</b> capture detected.<br><br>"
                    "PacketCircle has automatically switched to <b>IP mode</b> because "
                    "this encapsulation type does not carry Ethernet MAC addresses.<br><br>"
                    "Circles will be drawn based on IP endpoints.")
                .arg(QString::fromUtf8(result->encap_name)));
    }
    /* Find and hide the "Mode:" label too */
    if (m_row1Widget) {
        for (QObject *child : m_row1Widget->children()) {
            QLabel *lbl = qobject_cast<QLabel*>(child);
            if (lbl && lbl->text() == "Mode:") {
                lbl->setVisible(!m_wifiMode);
                break;
            }
        }
    }
    /* Update search bar hint for Wi-Fi */
    if (m_wifiMode) {
        if (m_searchLineEdit) m_searchLineEdit->setPlaceholderText("MAC, SSID, ap, signal quality  —  ? for help");
    } else if (wasWifi) {
        /* Restore normal hint when leaving Wi-Fi mode */
        updateSearchBarForMode();
    }

    updateViews();
    updateLegend();
    
    /* Initialize visible pairs - all pairs should be visible by default */
    /* This will be updated when updateViews() creates the list items */
    
    /* Initialize protocol filter - show all enabled categories by default (empty set = show all) */
    if (m_circleWidget) {
        QSet<QString> enabled_protocols;
        for (auto it = m_protocolCheckboxes.begin(); it != m_protocolCheckboxes.end(); ++it) {
            QCheckBox *checkbox = it.value();
            /* Only consider enabled checkboxes that are checked */
            if (checkbox->isEnabled() && checkbox->isChecked()) {
                QString category_name = it.key();
                /* Map category to its protocols */
                if (category_name == "ARP") {
                    enabled_protocols.insert("ARP");
                    enabled_protocols.insert("RARP");
                } else if (category_name == "ICMP") {
                    enabled_protocols.insert("ICMP");
                    enabled_protocols.insert("ICMPv6");
                } else if (category_name == "TCP") {
                    enabled_protocols.insert("TCP");
                } else if (category_name == "UDP") {
                    enabled_protocols.insert("UDP");
                } else if (category_name == "Infrastructure") {
                    enabled_protocols.insert("OSPF");
                    enabled_protocols.insert("BGP");
                    enabled_protocols.insert("RIP");
                    enabled_protocols.insert("RIPv2");
                    enabled_protocols.insert("EIGRP");
                    enabled_protocols.insert("ISIS");
                    enabled_protocols.insert("IS-IS");
                    enabled_protocols.insert("IGMP");
                    enabled_protocols.insert("IGMPv2");
                    enabled_protocols.insert("IGMPv3");
                    enabled_protocols.insert("PIM");
                    enabled_protocols.insert("VRRP");
                    enabled_protocols.insert("HSRP");
                    enabled_protocols.insert("SCTP");
                    enabled_protocols.insert("DCCP");
                } else if (category_name == "Unknown") {
                    enabled_protocols.insert("Unknown");
                    enabled_protocols.insert("IP");
                    enabled_protocols.insert("IPv4");
                    enabled_protocols.insert("IPv6");
                    enabled_protocols.insert("Ethernet");
                }
            }
        }
        /* If all enabled categories are checked, use empty set to show all (more efficient) */
        guint enabled_count = 0;
        guint checked_count = 0;
        for (auto it = m_protocolCheckboxes.begin(); it != m_protocolCheckboxes.end(); ++it) {
            if (it.value()->isEnabled()) {
                enabled_count++;
                if (it.value()->isChecked()) {
                    checked_count++;
                }
            }
        }
        if (enabled_count > 0 && checked_count == enabled_count) {
            enabled_protocols.clear();  /* Empty set = show all */
        }
        m_circleWidget->setProtocolFilter(enabled_protocols);
        if (m_graphWidget) m_graphWidget->setProtocolFilter(enabled_protocols);
    }
}

/* Slot implementations */
void MainWindow::onTop10Clicked()
{
    if (m_searchOverrideMode) exitSearchOverrideMode();
    m_topN = 10; m_top25Btn->setChecked(false); m_top50Btn->setChecked(false); updateViews(); updateLegend();
}
void MainWindow::onTop25Clicked()
{
    if (m_searchOverrideMode) exitSearchOverrideMode();
    m_topN = 25; m_top10Btn->setChecked(false); m_top50Btn->setChecked(false); updateViews(); updateLegend();
}
void MainWindow::onTop50Clicked()
{
    if (m_searchOverrideMode) exitSearchOverrideMode();
    m_topN = 50; m_top10Btn->setChecked(false); m_top25Btn->setChecked(false); updateViews(); updateLegend();
}
void MainWindow::onLineThicknessToggled(bool checked)
{
    if (m_circleWidget)
        m_circleWidget->setShowLineThickness(checked ? TRUE : FALSE);
    if (m_graphWidget)
        m_graphWidget->setShowLineThickness(checked ? TRUE : FALSE);
}

void MainWindow::onPacketsToggled(bool checked) { if (checked) { m_useBytes = FALSE; updateViews(); } }
void MainWindow::onBytesToggled(bool checked) { if (checked) { m_useBytes = TRUE; updateViews(); } }
void MainWindow::onCircleViewToggled(bool checked)
{
    if (!checked) return;
    m_viewStack->setCurrentIndex(0);
    if (m_graphControlsRow) m_graphControlsRow->setVisible(false);
}

void MainWindow::onTableViewToggled(bool checked)
{
    if (!checked) return;
    m_viewStack->setCurrentIndex(1);
    if (m_graphControlsRow) m_graphControlsRow->setVisible(false);
}

void MainWindow::onGraphViewToggled(bool checked)
{
    if (!checked) return;
    m_viewStack->setCurrentIndex(2);
    if (m_graphControlsRow) m_graphControlsRow->setVisible(true);
    /* Propagate current metric setting to graph widget */
    if (m_graphWidget) {
        m_graphWidget->setUseBytes(m_useBytes);
        m_graphWidget->setShowLineThickness(m_lineThicknessCheckBox
                                            ? (gboolean)m_lineThicknessCheckBox->isChecked()
                                            : FALSE);
    }
}

void MainWindow::onGraphEdgeColorChanged(int index)
{
    if (!m_graphWidget) return;
    QVariant v = m_graphEdgeColorCombo->itemData(index);
    int mode = v.isValid() ? v.toInt() : index;
    m_graphWidget->setEdgeColorMode(static_cast<GraphWidget::EdgeColorMode>(mode));
}

void MainWindow::onGraphNodeColorChanged(int index)
{
    if (!m_graphWidget) return;
    m_graphWidget->setNodeColorMode(static_cast<GraphWidget::NodeColorMode>(index));
}

void MainWindow::onGraphLayoutChanged(int index)
{
    if (!m_graphWidget) return;
    m_graphWidget->setLayoutMode(static_cast<GraphWidget::LayoutMode>(index));
}

void MainWindow::onGraphRelayout()
{
    if (m_graphWidget) m_graphWidget->relayout();
}

void MainWindow::onGraphLegendFilter(QList<comm_pair_t*> matchingPairs, bool active)
{
    if (!m_pairListWidget) return;

    QSet<comm_pair_t*> matchSet(matchingPairs.begin(), matchingPairs.end());

    /* Batch update — suppress itemChanged so we don't fire updateVisiblePairs for every tick */
    disconnect(m_pairListWidget, &QListWidget::itemChanged,
               this, &MainWindow::onPairListItemChanged);

    for (int i = 0; i < m_pairListWidget->count(); i++) {
        QListWidgetItem *item = m_pairListWidget->item(i);
        if (!item) continue;
        if (!active) {
            item->setCheckState(Qt::Checked);
        } else {
            comm_pair_t *primary   = (comm_pair_t*)item->data(Qt::UserRole).value<void*>();
            comm_pair_t *secondary = (comm_pair_t*)item->data(Qt::UserRole + 1).value<void*>();
            bool matches = (primary   && matchSet.contains(primary))
                        || (secondary && matchSet.contains(secondary));
            item->setCheckState(matches ? Qt::Checked : Qt::Unchecked);
        }
    }

    connect(m_pairListWidget, &QListWidget::itemChanged,
            this, &MainWindow::onPairListItemChanged);

    updateVisiblePairsFromWidgets();
}

void MainWindow::onMACToggled(bool checked) {
    if (checked) {
        m_useMAC = TRUE;
        updateSearchBarForMode();
        /* Trigger re-analysis when switching to MAC */
        circle_vis_reload_data();
    }
}
void MainWindow::onIPToggled(bool checked) {
    if (checked) {
        m_useMAC = FALSE;
        updateSearchBarForMode();
        /* Trigger re-analysis when switching to IP */
        circle_vis_reload_data();
    }
}

void MainWindow::resizeEvent(QResizeEvent *event)
{
    QMainWindow::resizeEvent(event);
    relayoutControls();
}

void MainWindow::relayoutControls()
{
    /* Responsive: merge row1 + row2 into single row if window is wide enough */
    /* For now, the two-row layout always shows both rows */
    /* Both rows are visible - they will wrap content naturally via QHBoxLayout */
}

void MainWindow::onLineClicked(comm_pair_t *pair, const QPoint &globalPos)
{
    if (!pair || !pair->src_addr || !pair->dst_addr)
        return;

    /* Close existing popup if any.
     * m_connectionPopup is a QPointer: it auto-nulls when the widget is
     * destroyed (via deleteLater from the auto-close timer).               */
    if (m_connectionPopup) {
        m_connectionPopup->hide();
        m_connectionPopup->deleteLater();
        m_connectionPopup = nullptr;
    }

    /* Find the reverse pair (B→A) so the popup can show merged port data */
    comm_pair_t *reversePair = nullptr;
    if (m_circle_pairs) {
        for (GList *iter = m_circle_pairs; iter; iter = iter->next) {
            comm_pair_t *p = (comm_pair_t *)iter->data;
            if (!p || !p->src_addr || !p->dst_addr || p == pair) continue;
            if (g_strcmp0(p->src_addr, pair->dst_addr) == 0 &&
                g_strcmp0(p->dst_addr, pair->src_addr) == 0) {
                reversePair = p;
                break;
            }
        }
    }

    /* Create and show popup immediately so basic info is visible right away */
    m_connectionPopup = new ConnectionPopup(pair, reversePair, m_useMAC, this);
    m_connectionPopup->setPerformanceFlags(m_enableL2Analysis, m_enableTransportStats, m_enableDeepInspection);

    QPoint popupPos = globalPos + QPoint(10, 10);
    QScreen *screen = QApplication::screenAt(globalPos);
    if (screen) {
        QRect screenGeom = screen->availableGeometry();
        QSize popupSize = m_connectionPopup->sizeHint();
        if (popupPos.x() + popupSize.width() > screenGeom.right())
            popupPos.setX(globalPos.x() - popupSize.width() - 10);
        if (popupPos.y() + popupSize.height() > screenGeom.bottom())
            popupPos.setY(globalPos.y() - popupSize.height() - 10);
    }
    m_connectionPopup->move(popupPos);

    /* In graph view: show the score button immediately as "Calculating…" so the user
     * knows it's coming; the deferred lambda below will enable it with final data. */
    if (m_graphWidget && m_viewStack && m_viewStack->currentIndex() == 2)
        m_connectionPopup->showScoreBtnCalculating();

    m_connectionPopup->show();

    /* Defer score computation to after first paint — keeps popup snappy on large traces */
    if (m_graphWidget && m_viewStack && m_viewStack->currentIndex() == 2) {
        QPointer<ConnectionPopup> safePopup(m_connectionPopup);
        QTimer::singleShot(0, this, [this, pair, reversePair, safePopup]() {
            if (!safePopup) return;
            QList<GraphWidget::ScoreFactor> healthFactors, anomalyFactors;
            qreal hs = 0.5, as = 0.0, rtMs = -1.0, tpBps = 0.0;
            m_graphWidget->getScoreBreakdown(pair, reversePair,
                                             &healthFactors, &anomalyFactors,
                                             &hs, &as, &rtMs, &tpBps);
            /* Fetch window stats from the pre-computed edge (same source as edge colour) */
            guint32 wMin = G_MAXUINT32, wMax = 0, wZero = 0;
            gdouble wAvg = 0.0, wZeroDur = 0.0;
            m_graphWidget->getEdgeWindowStats(pair, &wMin, &wMax, &wAvg, &wZero, &wZeroDur);
            safePopup->setGraphScores(hs, as, healthFactors, anomalyFactors,
                                      rtMs, tpBps, wMin, wMax, wAvg, wZero, wZeroDur);
        });
    }
}

/* ─── Table view: left-click opens ConnectionPopup ─────────────────────────
 * Mirrors the circle view arc-click behaviour: left-clicking a row in the
 * table view opens the same sessions/port breakdown popup.                  */
void MainWindow::onTableCellClicked(int row, int /*col*/)
{
    if (m_wifiMode) return;   /* Wi-Fi mode rows don't have ConnectionPopups */

    QTableWidgetItem *item = m_tableWidget->item(row, 1);
    if (!item) return;
    comm_pair_t *pair = static_cast<comm_pair_t*>(item->data(Qt::UserRole).value<void*>());
    if (!pair || !pair->src_addr || !pair->dst_addr) return;

    /* Position popup near the centre of the clicked row */
    QRect rowRect = m_tableWidget->visualRect(m_tableWidget->model()->index(row, 1));
    QPoint globalPos = m_tableWidget->viewport()->mapToGlobal(rowRect.center());
    onLineClicked(pair, globalPos);
}

/* ─── Table view: right-click context menu ─────────────────────────────────
 * Shows the same grouped context menu as the ConnectionPopup right-click,
 * but accessible directly from the table row without opening the popup first.
 *
 * Menu layout:
 *   ── Wireshark ──────────────────────
 *   Apply Filter in Wireshark
 *   Follow TCP Stream        (TCP only)
 *   TCP Throughput Graph     (TCP only)
 *   TCP Round-Trip Time Graph(TCP only)
 *   ── PacketCircle ───────────────────
 *   [Protocol] Protocol Information    (top-port match, optional)
 *   TCP / UDP Transport Details…       (optional)
 *   Connection Details…
 * ─────────────────────────────────────────────────────────────────────────*/
void MainWindow::onTableContextMenu(const QPoint &pos)
{
    if (m_wifiMode) return;

    int row = m_tableWidget->rowAt(pos.y());
    if (row < 0) return;

    QTableWidgetItem *item = m_tableWidget->item(row, 1);
    if (!item) return;
    comm_pair_t *pair = static_cast<comm_pair_t*>(item->data(Qt::UserRole).value<void*>());
    if (!pair || !pair->src_addr || !pair->dst_addr) return;

    m_tableWidget->selectRow(row);

    /* ── Determine top destination port ── */
    quint16 topPort  = 0;
    bool topIsTcp    = false;
    bool topIsUdp    = false;
    if (pair->dst_ports) {
        guint64 topCount = 0;
        GHashTableIter pit;
        gpointer pk, pv;
        g_hash_table_iter_init(&pit, pair->dst_ports);
        while (g_hash_table_iter_next(&pit, &pk, &pv)) {
            quint16 p    = (quint16)GPOINTER_TO_UINT(pk);
            port_stats_t *ps = (port_stats_t *)pv;
            if (ps && ps->count > topCount) {
                topCount = ps->count;
                topPort  = p;
                topIsTcp = ps->is_tcp;
                topIsUdp = ps->is_udp;
            }
        }
    }

    /* ── Build Wireshark filter strings ── */
    QString src = QString::fromUtf8(pair->src_addr);
    QString dst = QString::fromUtf8(pair->dst_addr);
    bool looksLikeMAC = (src.count(':') == 5 && dst.count(':') == 5);
    QString addrClause = looksLikeMAC
        ? QString("eth.addr == %1 && eth.addr == %2").arg(src).arg(dst)
        : QString("ip.addr == %1 && ip.addr == %2").arg(src).arg(dst);

    QString portClause;
    if (topPort > 0) {
        if (topIsTcp && topIsUdp)
            portClause = QString("(tcp.port == %1 || udp.port == %1)").arg(topPort);
        else if (topIsTcp)
            portClause = QString("tcp.port == %1").arg(topPort);
        else if (topIsUdp)
            portClause = QString("udp.port == %1").arg(topPort);
    }
    QString fullFilter = portClause.isEmpty()
        ? QString("(%1)").arg(addrClause)
        : QString("(%1 && %2)").arg(addrClause).arg(portClause);

    /* ── Build menu ── */
    QMenu menu;
    menu.setStyleSheet(pcMenuStyleSheet());

    /* ── Wireshark section ── */
    menu.addSection("Wireshark");
    QAction *filterAction     = menu.addAction("Apply Filter in Wireshark");
    QAction *followAction     = menu.addAction("Follow TCP Stream");
    QAction *throughputAction = menu.addAction("TCP Throughput Graph");
    QAction *rttAction        = menu.addAction("TCP Round-Trip Time Graph");

    bool hasTcp = pair->has_tcp;
    bool hasUdp = pair->has_udp;
    if (!hasTcp) {
        followAction->setEnabled(false);
        followAction->setText("Follow TCP Stream (TCP only)");
        throughputAction->setEnabled(false);
        throughputAction->setText("TCP Throughput Graph (TCP only)");
        rttAction->setEnabled(false);
        rttAction->setText("TCP Round-Trip Time Graph (TCP only)");
    }

    /* ── PacketCircle section ── */
    menu.addSection("PacketCircle");

    /* Match top port to a known protocol */
    struct ProtoMatch { int id; QString label; };
    ProtoMatch pm = {0, {}};
    if (topPort > 0) {
        quint16 p  = topPort;
        bool tcp   = topIsTcp;
        bool udp   = topIsUdp;
        if (tcp && p == 22)                                                 pm = { 13, "SSH / SFTP / SCP" };
        else if ((tcp||udp) && p == 443)                                    pm = {  1, "TLS / HTTPS" };
        else if (tcp && p == 80)                                            pm = {  2, "HTTP" };
        else if (tcp && (p == 445 || p == 135))                             pm = {  3, "SMB / DCE-RPC" };
        else if ((tcp||udp) && p == 88)                                     pm = {  4, "Kerberos" };
        else if (tcp && (p == 25 || p == 465 || p == 587))                 pm = {  5, "SMTP / Email" };
        else if (tcp && (p == 143 || p == 993))                             pm = {  5, "IMAP / Email" };
        else if (tcp && (p == 110 || p == 995))                             pm = {  5, "POP3 / Email" };
        else if (tcp && (p == 1433 || p == 3306 || p == 5432))             pm = {  6, "SQL Database" };
        else if ((tcp||udp) && (p == 5060 || p == 5061))                   pm = {  7, "VoIP / SIP" };
        else if (udp && (p == 67 || p == 68))                              pm = {  8, "DHCP" };
        else if ((udp||tcp) && p == 53)                                     pm = {  9, "DNS" };
        else if (tcp && (p == 389 || p == 636 || p == 3268 || p == 3269)) pm = { 10, "LDAP" };
        else if ((udp||tcp) && (p == 161 || p == 162))                     pm = { 11, "SNMP" };
        else if ((udp||tcp) && (p == 514 || p == 601 || p == 6514))       pm = { 12, "Syslog" };
        else if (tcp && (p == 21 || p == 20 || p == 990))                  pm = { 14, "FTP" };
        else if (tcp && (p == 23 || p == 992))                              pm = { 15, "Telnet" };
        else if (udp && p == 137)                                           pm = { 16, "NBNS" };
        else if (udp && p == 138)                                           pm = { 17, "NetBIOS Datagram" };
        else if (tcp && p == 139)                                           pm = { 18, "NetBIOS Session (NBSS)" };
    }

    QAction *protoAction    = nullptr;
    QAction *tcpStatAction  = nullptr;
    QAction *udpStatAction  = nullptr;

    if (pm.id > 0)
        protoAction = menu.addAction(pm.label + " Protocol Information");

    if (hasTcp)
        tcpStatAction = menu.addAction("TCP Transport Details\u2026");
    else if (hasUdp)
        udpStatAction = menu.addAction("UDP Transport Details\u2026");

    menu.addSeparator();
    QAction *detailsAction = menu.addAction("Connection Details\u2026");

    /* ── Execute menu ── */
    QAction *selected = menu.exec(m_tableWidget->viewport()->mapToGlobal(pos));
    if (!selected) return;

    /* Helper: find the reverse pair (reused by several branches) */
    auto findReverse = [&]() -> comm_pair_t* {
        if (!m_circle_pairs) return nullptr;
        for (GList *it = m_circle_pairs; it; it = it->next) {
            comm_pair_t *p = (comm_pair_t *)it->data;
            if (!p || !p->src_addr || !p->dst_addr || p == pair) continue;
            if (g_strcmp0(p->src_addr, pair->dst_addr) == 0 &&
                g_strcmp0(p->dst_addr, pair->src_addr) == 0)
                return p;
        }
        return nullptr;
    };

    if (selected == filterAction) {
        /* Apply address-only filter */
        QString addrFilter = QString("(%1)").arg(addrClause);
        QByteArray fb = addrFilter.toUtf8();
        plugin_if_apply_filter(fb.constData(), true);

    } else if (selected == followAction && hasTcp) {
        /* Apply filter then trigger Follow TCP Stream in Wireshark menu */
        QByteArray fb = fullFilter.toUtf8();
        plugin_if_apply_filter(fb.constData(), true);
        QTimer::singleShot(400, qApp, []() {
            for (QWidget *w : QApplication::topLevelWidgets()) {
                QMainWindow *mw = qobject_cast<QMainWindow*>(w);
                if (!mw || !mw->menuBar()) continue;
                for (QAction *topAct : mw->menuBar()->actions()) {
                    QMenu *topMenu = topAct->menu();
                    if (!topMenu) continue;
                    for (QAction *midAct : topMenu->actions()) {
                        QMenu *sub = midAct->menu();
                        if (!sub || !sub->title().contains("Follow", Qt::CaseInsensitive)) continue;
                        for (QAction *fa : sub->actions()) {
                            if (fa->text().contains("TCP Stream", Qt::CaseInsensitive) && fa->isEnabled()) {
                                fa->trigger(); return;
                            }
                        }
                    }
                }
            }
        });

    } else if (selected == throughputAction && hasTcp) {
        /* Apply filter then open TCP Throughput Graph */
        QByteArray fb = fullFilter.toUtf8();
        plugin_if_apply_filter(fb.constData(), true);
        QTimer::singleShot(400, qApp, []() {
            for (QWidget *w : QApplication::topLevelWidgets()) {
                QMainWindow *mw = qobject_cast<QMainWindow*>(w);
                if (!mw || !mw->menuBar()) continue;
                for (QAction *topAct : mw->menuBar()->actions()) {
                    QMenu *topMenu = topAct->menu();
                    if (!topMenu) continue;
                    for (QAction *midAct : topMenu->actions()) {
                        QMenu *sub = midAct->menu();
                        if (!sub || !sub->title().contains("TCP Stream Graph", Qt::CaseInsensitive)) continue;
                        for (QAction *ga : sub->actions()) {
                            if (ga->text().contains("Throughput", Qt::CaseInsensitive) && ga->isEnabled()) {
                                ga->trigger(); return;
                            }
                        }
                    }
                }
            }
        });

    } else if (selected == rttAction && hasTcp) {
        /* Apply filter then open TCP Round-Trip Time Graph */
        QByteArray fb = fullFilter.toUtf8();
        plugin_if_apply_filter(fb.constData(), true);
        QTimer::singleShot(400, qApp, []() {
            for (QWidget *w : QApplication::topLevelWidgets()) {
                QMainWindow *mw = qobject_cast<QMainWindow*>(w);
                if (!mw || !mw->menuBar()) continue;
                for (QAction *topAct : mw->menuBar()->actions()) {
                    QMenu *topMenu = topAct->menu();
                    if (!topMenu) continue;
                    for (QAction *midAct : topMenu->actions()) {
                        QMenu *sub = midAct->menu();
                        if (!sub || !sub->title().contains("TCP Stream Graph", Qt::CaseInsensitive)) continue;
                        for (QAction *ga : sub->actions()) {
                            if (ga->text().contains("Round Trip", Qt::CaseInsensitive) && ga->isEnabled()) {
                                ga->trigger(); return;
                            }
                        }
                    }
                }
            }
        });

    } else if (pm.id > 0 && selected == protoAction) {
        /* Create a temporary (hidden) ConnectionPopup as a data container,
         * then call its protocol-info method directly.  The popup is never
         * shown — hide() is a no-op and deleteLater() cleans it up after
         * the dialog returns.                                               */
        ConnectionPopup *tmp = new ConnectionPopup(pair, findReverse(), m_useMAC, this);
        tmp->setPerformanceFlags(m_enableL2Analysis, m_enableTransportStats, m_enableDeepInspection);
        tmp->triggerInfoForPort(topPort, pm.id);

    } else if (selected == tcpStatAction || selected == udpStatAction) {
        ConnectionPopup *tmp = new ConnectionPopup(pair, findReverse(), m_useMAC, this);
        tmp->setPerformanceFlags(m_enableL2Analysis, m_enableTransportStats, m_enableDeepInspection);
        tmp->triggerTransportDetails(selected == tcpStatAction);

    } else if (selected == detailsAction) {
        /* Same as a left-click: open the full ConnectionPopup */
        QRect rowRect = m_tableWidget->visualRect(m_tableWidget->model()->index(row, 1));
        QPoint globalPos = m_tableWidget->viewport()->mapToGlobal(rowRect.center());
        onLineClicked(pair, globalPos);
    }
}

/* ─── Arrow-toggle event filter ───────────────────────────────────────────
 * Clicking the non-checkbox area of a bidirectional pair row cycles the
 * direction arrow:  --> (forward only)  →  <-> (both)  →  <-- (reverse only)  →  …
 * The checkbox at the far left (~first 30 px) is left untouched.
 * ─────────────────────────────────────────────────────────────────────────── */
bool MainWindow::eventFilter(QObject *obj, QEvent *event)
{
    if (obj == m_pairListWidget->viewport() &&
        event->type() == QEvent::MouseButtonPress) {

        QMouseEvent *me = static_cast<QMouseEvent*>(event);

        /* Determine approximate checkbox width from the current style */
        int checkboxW = QApplication::style()->pixelMetric(QStyle::PM_IndicatorWidth)
                      + QApplication::style()->pixelMetric(QStyle::PM_CheckBoxLabelSpacing)
                      + 6; /* small safety margin */

        if (me->pos().x() > checkboxW) {
            QListWidgetItem *item = m_pairListWidget->itemAt(me->pos());
            if (item) {
                /* Only act on bidirectional items (secondary pair present) */
                comm_pair_t *secondary =
                    (comm_pair_t*)item->data(Qt::UserRole + 1).value<void*>();
                if (secondary) {
                    int dir = item->data(Qt::UserRole + 2).toInt();
                    dir = (dir + 1) % 3;   /* 0&rarr; &rarr; 1&#x2194; &rarr; 2&larr; &rarr; 0&rarr; &rarr; &hellip; */
                    item->setData(Qt::UserRole + 2, dir);
                    /* Refresh the text of this single item */
                    refreshPairListText();
                    /* Return true to consume the event so we don't accidentally
                     * trigger item selection / checkbox toggle */
                    return true;
                }
            }
        }
    }
    return QMainWindow::eventFilter(obj, event);
}

void MainWindow::onPairListContextMenu(const QPoint &pos)
{
    QMenu menu(m_pairListWidget);
    menu.setStyleSheet(pcMenuStyleSheet());
    QAction *actAll    = menu.addAction("Select All");
    QAction *actNone   = menu.addAction("Select None");
    QAction *actInvert = menu.addAction("Invert Selection");
    if (!m_highlightedPairItems.isEmpty()) {
        menu.addSeparator();
        menu.addAction("Select Search Results", this, &MainWindow::onSelectSearchResultsClicked);
    }
    QAction *chosen = menu.exec(m_pairListWidget->viewport()->mapToGlobal(pos));
    if      (chosen == actAll)    onSelectAllClicked();
    else if (chosen == actNone)   onSelectNoneClicked();
    else if (chosen == actInvert) onInvertPairSelection();
}

void MainWindow::onSelectAllClicked()
{
    /* Temporarily disconnect signal to avoid multiple update calls */
    disconnect(m_pairListWidget, &QListWidget::itemChanged, this, &MainWindow::onPairListItemChanged);

    for (int i = 0; i < m_pairListWidget->count(); i++) {
        QListWidgetItem *item = m_pairListWidget->item(i);
        if (item)
            item->setCheckState(Qt::Checked);
    }

    /* Reconnect signal */
    connect(m_pairListWidget, &QListWidget::itemChanged, this, &MainWindow::onPairListItemChanged);
    
    /* Sync table checkboxes and refresh */
    syncTableCheckboxesFromPairList();
    updateVisiblePairsFromWidgets();
    if (m_circleWidget) {
        m_circleWidget->update();
    }
}

void MainWindow::onSelectSearchResultsClicked()
{
    if (m_highlightedPairItems.isEmpty())
        return;

    /* Temporarily disconnect signal to avoid multiple update calls */
    disconnect(m_pairListWidget, &QListWidget::itemChanged, this, &MainWindow::onPairListItemChanged);

    QSet<int> highlighted(m_highlightedPairItems.begin(), m_highlightedPairItems.end());

    for (int i = 0; i < m_pairListWidget->count(); i++) {
        QListWidgetItem *item = m_pairListWidget->item(i);
        if (!item)
            continue;

        bool isMatch = highlighted.contains(i);
        item->setCheckState(isMatch ? Qt::Checked : Qt::Unchecked);
    }

    /* Reconnect signal */
    connect(m_pairListWidget, &QListWidget::itemChanged, this, &MainWindow::onPairListItemChanged);

    /* Sync table checkboxes and refresh */
    syncTableCheckboxesFromPairList();
    updateVisiblePairsFromWidgets();
    if (m_circleWidget) {
        m_circleWidget->update();
    }
}

void MainWindow::onSelectNoneClicked()
{
    /* Temporarily disconnect signal to avoid multiple update calls */
    disconnect(m_pairListWidget, &QListWidget::itemChanged, this, &MainWindow::onPairListItemChanged);

    for (int i = 0; i < m_pairListWidget->count(); i++) {
        QListWidgetItem *item = m_pairListWidget->item(i);
        if (item)
            item->setCheckState(Qt::Unchecked);
    }

    /* Reconnect signal */
    connect(m_pairListWidget, &QListWidget::itemChanged, this, &MainWindow::onPairListItemChanged);
    
    /* Sync table checkboxes and refresh */
    syncTableCheckboxesFromPairList();
    updateVisiblePairsFromWidgets();
    if (m_circleWidget) {
        m_circleWidget->update();
    }
}

void MainWindow::onInvertPairSelection()
{
    disconnect(m_pairListWidget, &QListWidget::itemChanged, this, &MainWindow::onPairListItemChanged);
    for (int i = 0; i < m_pairListWidget->count(); i++) {
        QListWidgetItem *item = m_pairListWidget->item(i);
        if (item)
            item->setCheckState(item->checkState() == Qt::Checked ? Qt::Unchecked : Qt::Checked);
    }
    connect(m_pairListWidget, &QListWidget::itemChanged, this, &MainWindow::onPairListItemChanged);
    syncTableCheckboxesFromPairList();
    updateVisiblePairsFromWidgets();
}

void MainWindow::onLineHovered(comm_pair_t *pair)
{
    if (!m_pairListWidget) return;

    /* Scan the live list every call — avoids dangling-pointer crash when the
     * list is rebuilt (top-N change, filter, reload) while a hover is active.
     * The list is ≤50 items so the scan is negligible.                        */
    QListWidgetItem *newHighlight = nullptr;
    for (int i = 0; i < m_pairListWidget->count(); i++) {
        QListWidgetItem *item = m_pairListWidget->item(i);
        if (!item) continue;
        void *primary   = item->data(Qt::UserRole).value<void*>();
        void *secondary = item->data(Qt::UserRole + 1).value<void*>();
        bool isMatch = pair && (primary == (void*)pair || secondary == (void*)pair);
        if (isMatch) {
            newHighlight = item;
            if (item != m_hoveredPairListItem) {
                item->setBackground(QColor(255, 160, 0, 200));
                item->setForeground(QColor(0, 0, 0));
            }
        } else if (item == m_hoveredPairListItem) {
            /* Was highlighted last time, clear it */
            item->setBackground(QBrush());
            item->setForeground(QBrush());
        }
    }

    m_hoveredPairListItem = newHighlight;  /* nullptr when pair==nullptr or not found */
    if (newHighlight)
        m_pairListWidget->scrollToItem(newHighlight, QAbstractItemView::EnsureVisible);
}

void MainWindow::onHelpClicked()
{
    /* Use custom QDialog instead of QMessageBox for full size control */
    QDialog *helpDialog = new QDialog(this);
    helpDialog->setWindowTitle(QString("Help - PacketCircle %1").arg(QLatin1String(PC_VERSION)));
    helpDialog->setMinimumSize(600, 400);
    helpDialog->resize(900, 650);
    /* Make dialog resizable */
    helpDialog->setSizeGripEnabled(true);
    
    QVBoxLayout *layout = new QVBoxLayout(helpDialog);
    
    /* Create QTextEdit for rich text display with proper sizing */
    QTextEdit *textEdit = new QTextEdit(helpDialog);
    textEdit->setReadOnly(true);
    textEdit->setMinimumWidth(500);
    textEdit->setMinimumHeight(300);
    
    /* Use plain text formatting - no bold for descriptions, only titles */
    textEdit->setHtml(
        "<style>"
        "h2 { font-weight: bold; margin-top: 10px; margin-bottom: 15px; }"
        "h3 { font-weight: bold; margin-top: 15px; margin-bottom: 10px; }"
        "p { font-weight: normal; margin-top: 8px; margin-bottom: 8px; line-height: 1.4; }"
        "li { font-weight: normal; margin-top: 6px; margin-bottom: 6px; }"
        "</style>"
        "<h2>PacketCircle Help</h2>"

        "<h3>Toolbar Controls:</h3>"
        "<p style='margin-left: 0; padding-left: 0; font-weight: normal;'>"
        "&bull; <b>Top 10/25/50</b>: Limit display to top N communication pairs<br/>"
        "&bull; <b>Weight</b>: Enable/disable line weight variation based on traffic volume<br/>"
        "&bull; <b>Packets/Bytes</b>: Sort pairs by packet count or byte count<br/>"
        "&bull; <b>Circle/Table</b>: Switch between circular visualization and table view<br/>"
        "&bull; <b>MAC/IP</b>: Display MAC address pairs or IP address pairs<br/>"
        "&bull; <b>?</b> (top right): Open this help window"
        "</p>"

        "<h3>Action Buttons:</h3>"
        "<p style='margin-left: 0; padding-left: 0; font-weight: normal;'>"
        "&bull; <b>Select All / Select None</b>: Show or hide all communication pairs<br/>"
        "&bull; <b>Select Results</b>: Select only the communication pairs matching the current search (enabled after a search produces results)<br/>"
        "&bull; <b>Filter</b>: Apply selected pairs as a Wireshark display filter (directional &mdash; filters by exact source&rarr;destination)<br/>"
        "&bull; <b>Clear</b>: Select all pairs, clear the Wireshark display filter, and show all packets<br/>"
        "&bull; <b>Reload</b>: Re-analyze current capture file (respects active Wireshark display filter)<br/>"
        "&bull; <b>PDF</b>: Export a 3-page PDF report (cover page, visualization + pair list, explanation page). Paper size and cover page fields are configured in <b>Settings &rarr; Configure Reports&hellip;</b>"
        "</p>"

        "<h3>Search & Highlighting:</h3>"
        "<p style='font-weight: normal;'>The search bar supports several query types. "
        "Press <b>Enter</b> to search; matching nodes flash red in the circle and the pair list blinks in sync.</p>"
        "<p style='margin-left: 0; padding-left: 0; font-weight: normal;'>"
        "&bull; <b>IP address</b> (partial): e.g. <code>192.168</code> or <code>10.0.0.1</code><br/>"
        "&bull; <b>CIDR range</b>: e.g. <code>10.0.0.0/8</code> or <code>172.16.0.0/12</code><br/>"
        "&bull; <b>MAC address</b> (partial, in MAC mode): e.g. <code>aa:bb</code> or <code>00:1a:2b</code><br/>"
        "&bull; <b>TCP port</b>: e.g. <code>TCP 443</code> or <code>tcp 23</code> &mdash; highlights all pairs that use the specified TCP port<br/>"
        "&bull; <b>UDP port</b>: e.g. <code>UDP 53</code> or <code>udp 5060</code> &mdash; highlights all pairs that use the specified UDP port"
        "</p>"
        "<p style='font-weight: normal;'>Port search works by inspecting the per-pair connection table (same data shown when clicking a line). "
        "It checks both directions of a communication pair. Clear the search box to remove all highlights.</p>"

        "<h3>Wi-Fi Monitor Mode:</h3>"
        "<p style='font-weight: normal;'>When a Wi-Fi monitor-mode capture is loaded (radiotap / 802.11), "
        "PacketCircle automatically switches to <b>Wi-Fi mode</b>. The MAC/IP toggle is hidden (Wi-Fi always uses MAC addresses), "
        "and connection colors reflect signal strength (RSSI) instead of protocol.</p>"
        "<p style='font-weight: normal;'>The <b>RSSI legend</b> at the bottom shows four signal quality bins "
        "(configurable via Settings &rarr; Wi-Fi Thresholds):</p>"
        "<p style='margin-left: 0; padding-left: 0; font-weight: normal;'>" +
        QString("&bull; <b>Excellent</b>: &ge; %1 dBm (green)<br/>"
                "&bull; <b>Good</b>: %2 to %3 dBm (yellow-green)<br/>"
                "&bull; <b>Fair</b>: %4 to %5 dBm (orange)<br/>"
                "&bull; <b>Poor</b>: &lt; %6 dBm (red)")
            .arg(m_wifiThresholdGroups[m_activeWifiThresholdGroup].rssi_excellent)
            .arg(m_wifiThresholdGroups[m_activeWifiThresholdGroup].rssi_good)
            .arg(m_wifiThresholdGroups[m_activeWifiThresholdGroup].rssi_excellent - 1)
            .arg(m_wifiThresholdGroups[m_activeWifiThresholdGroup].rssi_fair)
            .arg(m_wifiThresholdGroups[m_activeWifiThresholdGroup].rssi_good - 1)
            .arg(m_wifiThresholdGroups[m_activeWifiThresholdGroup].rssi_fair) +
        "</p>"
        "<p style='font-weight: normal;'>Node tooltips show Wi-Fi details: SSID, BSSID, channel, average/min/max RSSI, and retry count.</p>"
        "<h3>Wi-Fi Search Keywords:</h3>"
        "<p style='font-weight: normal;'>In Wi-Fi mode the search bar accepts additional query types:</p>"
        "<p style='margin-left: 0; padding-left: 0; font-weight: normal;'>"
        "&bull; <b>SSID</b> (partial): e.g. <code>MyNetwork</code> &mdash; highlights all station&#x2194;AP pairs associated with a matching SSID<br/>"
        "&bull; <b>BSSID / MAC</b> (partial): e.g. <code>aa:bb:cc</code> &mdash; matches the raw MAC, the BSSID field, or the SSID<br/>"
        "&bull; <b>ap</b>: highlights all access-point (BSSID) nodes in the circle<br/>"
        "&bull; <b>excellent</b> / <b>good</b> / <b>fair</b> / <b>poor</b>: highlights pairs whose average RSSI falls in the corresponding bin"
        "</p>"

        "<h3>Connection Details (Line Click):</h3>"
        "<p style='font-weight: normal;'>Click any communication line in the circle to open a "
        "<b>Connection Details</b> popup showing the port/socket breakdown for that pair. "
        "Data is aggregated from both directions (A&rarr;B and B&rarr;A).</p>"
        "<p style='margin-left: 0; padding-left: 0; font-weight: normal;'>"
        "&bull; <b>Protocol</b>: Transport protocol for each port (TCP, UDP, or TCP+UDP), detected per-port<br/>"
        "&bull; <b>Port</b>: Destination port number<br/>"
        "&bull; <b>Service</b>: Well-known service name (HTTP, HTTPS, SSH, Telnet, DNS, SMB, etc.)<br/>"
        "&bull; <b>Packets</b>: Number of packets observed on that port<br/>"
        "&bull; <b>% of Total</b>: Share of total traffic for the pair"
        "</p>"
        "<p style='font-weight: normal;'><b>Right-click</b> a row in the popup to access:</p>"
        "<p style='margin-left: 0; padding-left: 0; font-weight: normal;'>"
        "&bull; <b>Apply Filter in Wireshark</b>: Sets a bidirectional display filter matching both addresses "
        "and the selected port. Uses <code>ip.addr</code> / <code>eth.addr</code> for addresses "
        "and <code>tcp.port</code> or <code>udp.port</code> for the port.<br/>"
        "&bull; <b>Follow TCP Stream</b>: Opens Wireshark's TCP stream reassembly dialog for that connection (TCP only).<br/>"
        "&bull; <b>TCP Throughput Graph</b>: Opens Wireshark's TCP throughput time-series graph for the selected stream (TCP only).<br/>"
        "&bull; <b>TCP Round-Trip Time Graph</b>: Opens Wireshark's TCP RTT graph for the selected stream (TCP only).<br/>"
        "&bull; <b>Protocol Info</b> (port-dependent): Opens a detailed protocol information dialog &mdash; see below."
        "</p>"
        "<p style='font-weight: normal;'>The popup auto-closes when the mouse leaves it. "
        "It remains open while a right-click context menu is active.</p>"

        "<h3>Protocol Information Dialogs:</h3>"
        "<p style='font-weight: normal;'>When you right-click a row in the Connection Details popup, "
        "port-specific protocol information options appear based on the destination port. "
        "Each dialog extracts and displays deep protocol details from the captured packets.</p>"
        "<p style='margin-left: 0; padding-left: 0; font-weight: normal;'>"
        "&bull; <b>TLS/SSL Info</b> (ports 443, 465, 993, 995, 8443): Certificate details (subject, issuer, validity, SANs), "
        "negotiated cipher suites, TLS version, ALPN, SNI, and JA3/JA4 fingerprints.<br/>"
        "&bull; <b>HTTP Info</b> (ports 80, 8080, 8000, 8888): Request/response headers, methods, status codes, URIs, "
        "content types, server info, cookies, and user agents.<br/>"
        "&bull; <b>SMB/CIFS &amp; DCE/RPC Info</b> (ports 445, 139): Share names, file operations, tree operations, "
        "named pipe access, DCE/RPC interface UUIDs, and operation names.<br/>"
        "&bull; <b>Kerberos Info</b> (port 88): Ticket details (TGT/TGS), client and server principals, realms, "
        "encryption types, pre-authentication data, and service principal names.<br/>"
        "&bull; <b>Email Info</b> (ports 25, 110, 143, 587, 993, 995): SMTP senders/recipients/subjects, "
        "IMAP mailbox operations, POP3 commands, server responses, and authentication methods.<br/>"
        "&bull; <b>SQL Database Info</b> (ports 1433, 3306, 5432): Queries, database/schema names, authentication details, "
        "server version, application name, command/response statistics, and error messages. "
        "Supports MSSQL/TDS, MySQL/MariaDB, and PostgreSQL.<br/>"
        "&bull; <b>VoIP/SIP Info</b> (ports 5060, 5061): SIP Call-IDs, method and status code counts, "
        "From/To addresses, user agents, RTP payload types and SSRCs, setup methods, and H.223 mux entries."
        "</p>"

        "<h3>Filtering:</h3>"
        "<p style='font-weight: normal;'>The <b>Filter</b> button applies a Wireshark display filter for the currently checked pairs. "
        "The direction arrow on each pair controls what gets filtered:<br/>"
        "&bull; <b>--&gt;</b> (forward) &mdash; filters only A &rarr; B packets<br/>"
        "&bull; <b>&lt;-&gt;</b> (both) &mdash; filters both A &rarr; B and B &rarr; A packets<br/>"
        "&bull; <b>&lt;--</b> (reverse) &mdash; filters only B &rarr; A packets<br/>"
        "IPv6 addresses automatically use <code>ipv6.src</code> / <code>ipv6.dst</code> filter fields.</p>"
        "<p style='font-weight: normal;'>The <b>Clear</b> button resets everything: selects all pairs "
        "and sends an empty display filter to Wireshark so all packets are visible again.</p>"
        "<p style='font-weight: normal;'>Filters applied from the connection popup use <b>bidirectional</b> address matching "
        "so traffic in both directions is always included.</p>"

        "<h3>Protocol Legend (standard mode):</h3>"
        "<p style='font-weight: normal;'>In standard (non-Wi-Fi) mode, the protocol legend at the bottom shows protocol categories with checkboxes:</p>"
        "<p style='margin-left: 0; padding-left: 0; font-weight: normal;'>"
        "&bull; <b>ARP</b>: Address Resolution Protocol (ARP, RARP)<br/>"
        "&bull; <b>ICMP</b>: Internet Control Message Protocol (ICMP, ICMPv6)<br/>"
        "&bull; <b>TCP</b>: Transmission Control Protocol<br/>"
        "&bull; <b>UDP</b>: User Datagram Protocol<br/>"
        "&bull; <b>Infra</b>: Routing and infrastructure protocols (OSPF, BGP, RIP, EIGRP, ISIS, IGMP, PIM, VRRP, HSRP, SCTP, DCCP, STP/RSTP/MSTP/PVST, LLDP, LACP, CDP, VTP, MPLS)<br/>"
        "&bull; <b>Unknown</b>: Unidentified or generic protocols (IP, IPv4, IPv6, Ethernet)"
        "</p>"
        "<p style='font-weight: normal;'>Uncheck a protocol category to hide its connections in the circle view. "
        "Protocols not found in the current capture show a dash (N/A). "
        "Mixed TCP+UDP pairs display as alternating dotted lines.</p>"

        "<h3>Node Pair List:</h3>"
        "<p style='font-weight: normal;'>Each row shows one connection. Bidirectional pairs (A&lt;-&gt;B) are merged into a "
        "single row. The <b>checkbox</b> controls visibility of the connection line in the circle. "
        "The <b>direction arrow</b> (--&gt; / &lt;-&gt; / &lt;--) controls the filter direction &mdash; click anywhere on the row "
        "<i>outside</i> the checkbox to cycle through the three states. "
        "Addresses are automatically truncated with \"...\" to fit the available panel width "
        "&mdash; drag the splitter to resize. MAC addresses and vendor names always show in full until space runs out, "
        "just like hostnames.</p>"

        "<h3>Node Tooltips:</h3>"
        "<p style='font-weight: normal;'>Hover over a node in the circle to see detailed information:</p>"
        "<p style='margin-left: 0; padding-left: 0; font-weight: normal;'>"
        "&bull; MAC and IP address<br/>"
        "&bull; Bytes and packets sent/received<br/>"
        "&bull; Services (target ports): A list of destination ports targeted on this node, "
        "sorted by packet count. Well-known ports are resolved to service names "
        "(e.g. HTTP/80, HTTPS/443, SMB/445, SSH/22, DNS/53, RDP/3389, etc.)."
        "</p>"

        "<h3>PDF Export:</h3>"
        "<p style='font-weight: normal;'>Click the <b>PDF</b> button to generate a 3-page PDF report:</p>"
        "<p style='margin-left: 0; padding-left: 0; font-weight: normal;'>"
        "&bull; <b>Page 1 &mdash; Cover page</b>: PacketCircle logo, report title, and configurable metadata (Company Name, Prepared by, Project, Comments, Date)<br/>"
        "&bull; <b>Page 2 &mdash; Report page</b>: the currently active view (Circle, Table, or Graph) at high resolution; the full communication pair list; a protocol legend (Circle/Table) or graph legend (Graph) below the visualization<br/>"
        "&bull; <b>Page 3 &mdash; Explanation page</b>: plain-language interpretation guidance for the active view, plus common sections covering the pair list, active filters, Top-N setting, and metric"
        "</p>"
        "<p style='font-weight: normal;'>Paper size (A4 or Legal, landscape) and all cover page fields are configured in "
        "<b>Settings &rarr; Configure Reports&hellip;</b>. Settings are saved in <code>~/.PacketCircle/settings.ini</code>.</p>"

        "<h3>Preferences:</h3>"
        "<p style='font-weight: normal;'>PacketCircle automatically saves your preferences to "
        "<code>~/.PacketCircle/settings.ini</code>. The following settings are remembered between sessions:</p>"
        "<p style='margin-left: 0; padding-left: 0; font-weight: normal;'>"
        "&bull; Window position and size<br/>"
        "&bull; Splitter position (circle vs. pair list width)<br/>"
        "&bull; Top N selection (10/25/50)<br/>"
        "&bull; Packets vs. Bytes mode<br/>"
        "&bull; MAC vs. IP mode<br/>"
        "&bull; Circle vs. Table view<br/>"
        "&bull; Line weight checkbox state"
        "</p>"

        "<h3>Graph View:</h3>"
        "<p style='font-weight: normal;'>The <b>Graph</b> view renders the same communication pairs as a "
        "force-directed network topology. Switch to it with the <b>Graph</b> button in the toolbar. "
        "The graph controls row (Edge, Node, Layout, Re-layout, Zoom) appears while in Graph mode.</p>"
        "<p style='margin-left: 0; padding-left: 0; font-weight: normal;'>"
        "&bull; <b>Edge: Protocol</b> — lines colored by dominant application protocol (same palette as circle view)<br/>"
        "&bull; <b>Edge: TCP Health</b> — green=healthy / yellow=moderate / orange=degraded / red=unhealthy<br/>"
        "&bull; <b>Edge: Anomaly Score</b> — green=clean / yellow=noteworthy / orange=suspicious / red=anomalous<br/>"
        "&bull; <b>Edge: Response Time</b> — green=&lt;5ms / yellow-green=5-50ms / yellow=50-200ms / orange=200-500ms / red=&gt;500ms<br/>"
        "&bull; <b>Edge: Throughput</b> — blue=&lt;10KB/s / green=10-100KB/s / yellow=100KB-1MB/s / orange=1-10MB/s / red=&gt;10MB/s<br/>"
        "&bull; <b>Edge: TCP Window</b> — green=healthy / yellow=mild pressure / orange=constrained / red=zero-window stall<br/>"
        "&bull; <b>Edge: High Risk</b> — grey=safe / yellow=elevated (SSH, MQTT, SNMP) / orange=high (RDP, WinRM, AnyDesk) / red=critical (Telnet, FTP, VNC, raw X11) / violet=VPN/TOR; hover an edge for a tooltip listing detected risk signals<br/>"
        "&bull; <b>Node: Service/Port</b> — color by dominant destination port / service<br/>"
        "&bull; <b>Node: Role</b> — Internal (RFC-1918) / External / Broadcast / MAC<br/>"
        "&bull; <b>Node: Protocol</b> — dominant L7 protocol<br/>"
        "&bull; <b>Node: Function</b> — service category by inbound ports: Remote Access (crimson) / Interactive Shell (orange) / Messaging (teal) / File Transfer (green) / Other (grey)<br/>"
        "&bull; <b>Layout modes</b>: Force-directed, Star, Circular, Grid, Cluster, "
        "Concentric (rings by connection count), Hierarchical (External / Gateway / Server / Client tiers), "
        "Radial (BFS rings from most-connected node)<br/>"
        "&bull; <b>Cluster grouping</b> adapts to the active node colour mode: "
        "<i>Node: Function</i> &rarr; clusters by service category; "
        "<i>Node: Role</i> &rarr; clusters by network role; "
        "all other modes &rarr; clusters by /24 subnet<br/>"
        "&bull; <b>Zoom</b>: scroll wheel or -/1:1/+ buttons<br/>"
        "&bull; <b>Pan</b>: middle-mouse drag <i>or</i> hold Space then left-drag<br/>"
        "&bull; <b>Move node</b>: left-drag a node"
        "</p>"
        "<p style='font-weight: normal;'>In <b>TCP Health</b> or <b>Anomaly Score</b> edge mode, "
        "clicking a line opens the Connection Details popup with an additional <b>Score</b> button "
        "in the header. Click Score to see a breakdown of every signal that contributed to the rating "
        "with its direction (+/-) and percentage. "
        "For TCP connections the Score breakdown also shows TCP Window statistics: "
        "min/max/average window size, zero-window event count, and maximum zero-window stall duration. "
        "For full scoring algorithm details see <b>graph-scores.md</b> in the repository.</p>"
        "<p style='font-weight: normal;'>Scoring thresholds can be customised in "
        "<b>Settings &rarr; Graph Thresholds</b>. Three built-in profiles are provided: "
        "<b>Default</b> (balanced), <b>Strict</b> (flags problems earlier — for production / SLA environments), "
        "and <b>Tolerant</b> (only flags obvious issues — for lab / internet traffic). "
        "Custom profiles can also be created and named.</p>"

        "<h3>Layout &amp; Colour Combination Guide</h3>"
        "<p style='font-weight: normal;'>Each layout mode reveals a different structural aspect of the traffic. "
        "Pairing it with the right edge and node colour modes sharpens the analysis. "
        "The table below lists the most useful combinations.</p>"
        "<table border='1' cellspacing='0' cellpadding='4' style='font-weight: normal; border-collapse: collapse;'>"
        "<tr style='font-weight: bold;'>"
        "  <td>Layout</td><td>Edge colour</td><td>Node colour</td><td>Best used for</td>"
        "</tr>"
        "<tr>"
        "  <td><b>Force-directed</b></td><td>Protocol</td><td>Role</td>"
        "  <td>General overview — organic clustering shows which hosts talk to each other most; "
        "      node role (Internal / External / Broadcast) gives instant topology context</td>"
        "</tr>"
        "<tr>"
        "  <td><b>Force-directed</b></td><td>TCP Health</td><td>Role</td>"
        "  <td>Performance triage — red/orange edges stand out in the organic layout; "
        "      quickly locate degraded connections without knowing the topology in advance</td>"
        "</tr>"
        "<tr>"
        "  <td><b>Hierarchical</b></td><td>TCP Health</td><td>Service / Port</td>"
        "  <td>Tier-by-tier health check — four fixed tiers (External → Gateway → Server → Client) "
        "      show exactly which layer has unhealthy connections; service colour on nodes "
        "      identifies the affected application</td>"
        "</tr>"
        "<tr>"
        "  <td><b>Hierarchical</b></td><td>Response Time</td><td>Service / Port</td>"
        "  <td>Latency / SLA analysis — the server tier is visually isolated; "
        "      response-time colour on edges shows which services are slow; "
        "      combine with the Strict threshold profile for tight SLA environments</td>"
        "</tr>"
        "<tr>"
        "  <td><b>Radial</b></td><td>Anomaly Score</td><td>Role</td>"
        "  <td>Scan &amp; sweep detection — BFS places the most-connected node (potential scanner) "
        "      at the centre; anomaly-score edge colour highlights port-sweep and flood patterns "
        "      radiating outward</td>"
        "</tr>"
        "<tr>"
        "  <td><b>Radial</b></td><td>Protocol</td><td>Protocol</td>"
        "  <td>Protocol spread from a hub — shows which protocols a dominant node uses with each "
        "      peer; useful for diagnosing unexpected L7 traffic from a gateway or proxy</td>"
        "</tr>"
        "<tr>"
        "  <td><b>Cluster</b></td><td>Protocol</td><td>Role</td>"
        "  <td>Subnet segmentation — hosts are grouped by /24 subnet; cross-cluster edges "
        "      immediately show inter-segment communication; protocol colour reveals what "
        "      is crossing subnet boundaries</td>"
        "</tr>"
        "<tr>"
        "  <td><b>Cluster</b></td><td>Anomaly Score</td><td>Role</td>"
        "  <td>Lateral movement detection — suspicious cross-subnet traffic stands out "
        "      as orange/red edges between clusters; role colour distinguishes internal "
        "      pivots from external ingress</td>"
        "</tr>"
        "<tr>"
        "  <td><b>Concentric</b></td><td>Throughput</td><td>Protocol</td>"
        "  <td>Bandwidth consumers — high-degree nodes (most connections) sit in the inner "
        "      rings; throughput edge colour immediately identifies high-bandwidth flows; "
        "      node protocol colour shows what application is responsible</td>"
        "</tr>"
        "<tr>"
        "  <td><b>Concentric</b></td><td>TCP Health</td><td>Role</td>"
        "  <td>Infrastructure health at a glance — inner-ring nodes are the busiest; "
        "      red/orange edges show where health degrades under load</td>"
        "</tr>"
        "<tr>"
        "  <td><b>Star</b></td><td>Response Time</td><td>Service / Port</td>"
        "  <td>Client&ndash;server latency — places one central server with all clients "
        "      around it; response-time colour on spokes shows per-client latency; "
        "      click a node to hide/show its spoke for a cleaner view</td>"
        "</tr>"
        "<tr>"
        "  <td><b>Force-directed</b></td><td>High Risk</td><td>Role</td>"
        "  <td>Instant risk audit — red/critical edges (Telnet, FTP, VNC) and violet VPN/TOR links stand out; "
        "      node role identifies whether risky services are exposed to external hosts</td>"
        "</tr>"
        "<tr>"
        "  <td><b>Cluster</b></td><td>High Risk</td><td>Function</td>"
        "  <td>Service risk mapping — hosts grouped by function category (Remote Access, File Transfer, etc.); "
        "      risky edge colours immediately reveal which service categories are using insecure protocols</td>"
        "</tr>"
        "<tr>"
        "  <td><b>Cluster (Wi-Fi mode)</b></td><td>Wi-Fi RSSI</td><td>Role</td>"
        "  <td>Wi-Fi site survey — clusters group by 802.11 frame type "
        "      (Access Points / Management / Data Stations / Broadcast); "
        "      RSSI edge colour (green &ge;-55 dBm → red &lt;-75 dBm) shows signal quality "
        "      per link at a glance</td>"
        "</tr>"
        "</table>"

        "<h3>Keyboard &amp; Mouse Reference</h3>"
        "<p style='font-weight: normal;'><b>Pair list (right panel)</b></p>"
        "<table cellspacing='0' cellpadding='2' style='font-weight: normal;'>"
        "<tr><td width='180'><b>Check / uncheck</b></td><td>Toggle pair visibility in all views</td></tr>"
        "<tr><td><b>Click label</b></td><td>Cycle direction filter: &rarr; (outbound) / &harr; (both) / &larr; (inbound)</td></tr>"
        "<tr><td><b>Ctrl+A / Select All</b></td><td>Check all pairs</td></tr>"
        "<tr><td><b>Invert button</b></td><td>Flip every checkbox (check &harr; uncheck)</td></tr>"
        "<tr><td><b>Select None</b></td><td>Uncheck all pairs</td></tr>"
        "<tr><td><b>Select Results</b></td><td>Check only pairs matching the current search</td></tr>"
        "</table>"
        "<p style='font-weight: normal;'><b>Circle view</b></p>"
        "<table cellspacing='0' cellpadding='2' style='font-weight: normal;'>"
        "<tr><td width='180'><b>Left-click line</b></td><td>Open Connection Details popup</td></tr>"
        "<tr><td><b>Hover over line</b></td><td>Highlight matching pair in right panel</td></tr>"
        "<tr><td><b>Left-click node</b></td><td>Hide / show all connections for that host (click again to restore)</td></tr>"
        "<tr><td><b>Dashed line</b></td><td>One-way connection (no reverse traffic)</td></tr>"
        "</table>"
        "<p style='font-weight: normal;'><b>Table view</b></p>"
        "<table cellspacing='0' cellpadding='2' style='font-weight: normal;'>"
        "<tr><td width='180'><b>Left-click row</b></td><td>Open Connection Details popup</td></tr>"
        "<tr><td><b>Right-click row</b></td><td>Context menu (filter, follow stream, protocol info)</td></tr>"
        "<tr><td><b>Hover row</b></td><td>Highlight matching pair in right panel</td></tr>"
        "</table>"
        "<p style='font-weight: normal;'><b>Graph view</b></p>"
        "<table cellspacing='0' cellpadding='2' style='font-weight: normal;'>"
        "<tr><td width='180'><b>Scroll wheel</b></td><td>Zoom in / out</td></tr>"
        "<tr><td><b>Middle-drag</b></td><td>Pan the canvas</td></tr>"
        "<tr><td><b>Space + left-drag</b></td><td>Pan the canvas (keyboard-friendly alternative)</td></tr>"
        "<tr><td><b>Left-drag node</b></td><td>Move individual node to a custom position</td></tr>"
        "<tr><td><b>Left-click node</b></td><td>Hide / show all edges for that host (click again to restore)</td></tr>"
        "<tr><td><b>Left-click edge</b></td><td>Open Connection Details popup</td></tr>"
        "<tr><td><b>Hover over edge</b></td><td>Highlight matching pair in right panel</td></tr>"
        "<tr><td><b>Dashed edge</b></td><td>One-way connection (no reverse traffic)</td></tr>"
        "<tr><td><b>Ctrl+left-drag cluster</b></td><td>Move an entire cluster group as a unit (Cluster layout only)</td></tr>"
        "<tr><td><b>Re-layout button</b></td><td>Reset to automatic layout (clears manual node moves)</td></tr>"
        "<tr><td><b>1:1 button</b></td><td>Reset zoom to 100 %</td></tr>"
        "</table>"
    );
    
    /* Footer row: "Built with..." label + OK button side by side */
    QHBoxLayout *footerRow = new QHBoxLayout();
    footerRow->setContentsMargins(0, 2, 0, 0);

    QLabel *footerLabel = new QLabel(helpDialog);
    footerLabel->setText(
        QString::fromUtf8("Built with \xe2\x9d\xa4\xef\xb8\x8f for the network analysis community \u2014 "
        "<a href=\"https://github.com/netwho/PacketCircle\">https://github.com/netwho/PacketCircle</a>")
    );
    footerLabel->setOpenExternalLinks(true);
    footerLabel->setStyleSheet(m_darkTheme ? "color: #888; font-size: 11px;" : "color: #999; font-size: 11px;");

    QPushButton *okButton = new QPushButton("OK", helpDialog);
    connect(okButton, &QPushButton::clicked, helpDialog, &QDialog::accept);

    footerRow->addWidget(footerLabel, 1);
    footerRow->addWidget(okButton, 0);

    layout->addWidget(textEdit);
    layout->addLayout(footerRow);
    
    helpDialog->exec();
    delete helpDialog;
}

void MainWindow::onApplyFilterClicked()
{
    QString filter = createFilterString();
    if (filter.isEmpty()) {
        QMessageBox::warning(this, "No Selection", 
                            "Please select communication pairs to filter.");
        return;
    }

    QByteArray filter_bytes = filter.toUtf8();
    plugin_if_apply_filter(filter_bytes.constData(), true);
}

void MainWindow::onClearFilterClicked()
{
    /* Select all pairs to show all connections in the circle */
    onSelectAllClicked();

    /* Apply an empty filter to Wireshark to clear the display filter and show all packets */
    plugin_if_apply_filter("", true);

    /* Also empty the search field (clearing emits textChanged → applySearchFilter(""))
     * and reload the data so the view returns to its full, unfiltered state. */
    if (m_searchLineEdit)
        m_searchLineEdit->clear();
    onReloadDataClicked();
}

void MainWindow::onSavePDFClicked()
{
    /* Ask user where to save */
    QString defaultName = QString("PacketCircle_Report_%1.pdf")
                              .arg(QDateTime::currentDateTime().toString("yyyyMMdd_HHmmss"));
    QString filePath = QFileDialog::getSaveFileName(this, "Save PDF Report", defaultName, "PDF Files (*.pdf)");
    if (filePath.isEmpty())
        return;

    /* --- Setup PDF writer --- */
    QPageSize::PageSizeId psId = (m_reportPaperSize == 1) ? QPageSize::Legal : QPageSize::A4;
    QPdfWriter writer(filePath);
    writer.setPageSize(QPageSize(psId));
    writer.setPageOrientation(QPageLayout::Landscape);
    writer.setResolution(300);
    writer.setPageMargins(QMarginsF(12, 12, 12, 12), QPageLayout::Millimeter);

    QPainter painter(&writer);
    if (!painter.isActive()) {
        QMessageBox::warning(this, "PDF Error", "Failed to create PDF file.");
        return;
    }

    const int pageW = writer.width();
    const int pageH = writer.height();
    const int dpi   = writer.resolution();
    auto mm = [dpi](double millimeters) -> int {
        return qRound(millimeters * dpi / 25.4);
    };

    QPixmap logo(":/packetcircle/PacketCircle.png");
    QString nowStr = QDateTime::currentDateTime().toString("yyyy-MM-dd HH:mm");
    int currentView = m_viewStack ? m_viewStack->currentIndex() : 0;
    QString viewName = (currentView == 1) ? "Table" : (currentView == 2) ? "Graph" : "Circle";

    /* ─────────────────────────────────────────────────────────────────
     * Helper: draw the standard PDF page footer
     * ───────────────────────────────────────────────────────────────── */
    auto drawFooter = [&](int pageNum) {
        QFont fFont("Helvetica", 7);
        painter.setFont(fFont);
        painter.setPen(QColor(140, 140, 140));
        QFontMetrics ffm(fFont, &writer);
        int fh = ffm.height();
        painter.setPen(QPen(QColor(200, 200, 200), mm(0.2)));
        painter.drawLine(0, pageH - fh - mm(3), pageW, pageH - fh - mm(3));
        painter.setPen(QColor(140, 140, 140));
        painter.drawText(0, pageH - fh - mm(1), pageW / 2, fh, Qt::AlignLeft,
                         QString("PacketCircle %1  —  %2").arg(QLatin1String(PC_VERSION), nowStr));
        painter.drawText(pageW / 2, pageH - fh - mm(1), pageW / 2, fh, Qt::AlignRight,
                         QString("Page %1 of 3").arg(pageNum));
    };

    /* ─────────────────────────────────────────────────────────────────
     * Helper: draw the compact page header (logo + title + meta line)
     * ───────────────────────────────────────────────────────────────── */
    auto drawPageHeader = [&]() -> int {
        int y = 0;
        int lh = mm(14);
        if (!logo.isNull()) {
            QPixmap sl = logo.scaledToHeight(lh, Qt::SmoothTransformation);
            painter.drawPixmap(0, y, sl);
            QFont hf("Helvetica", 16, QFont::Bold);
            painter.setFont(hf);
            painter.setPen(Qt::black);
            painter.drawText(sl.width() + mm(4), y, pageW - sl.width() - mm(4), lh,
                             Qt::AlignVCenter | Qt::AlignLeft, "PacketCircle Report");
        } else {
            QFont hf("Helvetica", 16, QFont::Bold);
            painter.setFont(hf);
            painter.setPen(Qt::black);
            painter.drawText(0, y, pageW, lh, Qt::AlignVCenter | Qt::AlignLeft, "PacketCircle Report");
        }
        y += lh + mm(1);

        /* Meta line */
        QFont mf("Helvetica", 8);
        painter.setFont(mf);
        painter.setPen(QColor(100, 100, 100));
        QFontMetrics mfm(mf, &writer);
        QString meta;
        if (!m_reportCompany.isEmpty())    meta += m_reportCompany + "  |  ";
        if (!m_reportPreparedBy.isEmpty()) meta += "Prepared by: " + m_reportPreparedBy + "  |  ";
        meta += QString("View: %1  |  Top %2 pairs  |  Sorted by %3  |  %4")
                    .arg(viewName).arg(m_topN)
                    .arg(m_useBytes ? "bytes" : "packets")
                    .arg(nowStr);
        painter.drawText(0, y, pageW, mfm.height() + mm(1), Qt::AlignVCenter, meta);
        y += mfm.height() + mm(3);

        /* Separator */
        painter.setPen(QPen(QColor(180, 180, 180), mm(0.3)));
        painter.drawLine(0, y, pageW, y);
        y += mm(4);
        return y;
    };

    /* ─────────────────────────────────────────────────────────────────
     * Helper: draw the pair list table into a given rectangle
     * ───────────────────────────────────────────────────────────────── */
    auto drawPairList = [&](int lx, int ly, int lw, int lh) {
        QFont thf("Helvetica", 8, QFont::Bold);
        QFont tf("Courier", 7);
        QFontMetrics thfm(thf, &writer);
        QFontMetrics tfm(tf, &writer);
        int rowH = tfm.height() + mm(1.2);

        int pad = mm(1);
        int uw  = lw - 2 * pad;
        int cSrc  = (int)(uw * 0.30);
        int cDst  = (int)(uw * 0.30);
        int cPkts = (int)(uw * 0.19);
        int cBytes = uw - cSrc - cDst - cPkts;

        /* Header row */
        int hrH = thfm.height() + mm(1.8);
        painter.setPen(Qt::NoPen);
        painter.setBrush(QColor(55, 55, 55));
        painter.drawRect(lx, ly, lw, hrH);
        painter.setFont(thf);
        painter.setPen(Qt::white);
        int tx = lx + pad;
        int tvc = ly + (hrH - thfm.height()) / 2;
        painter.drawText(tx, tvc, cSrc, hrH,  Qt::AlignVCenter, "Source");        tx += cSrc;
        painter.drawText(tx, tvc, cDst, hrH,  Qt::AlignVCenter, "Destination");   tx += cDst;
        painter.drawText(tx, tvc, cPkts - pad, hrH, Qt::AlignVCenter | Qt::AlignRight, "Pkts"); tx += cPkts;
        painter.drawText(tx, tvc, cBytes - pad, hrH, Qt::AlignVCenter | Qt::AlignRight, "Bytes");
        ly += hrH;

        /* Data rows */
        painter.setFont(tf);
        int rowCount = 0;
        int maxRows  = (lh - hrH) / rowH;
        for (int i = 0; i < m_pairListWidget->count() && rowCount < maxRows; i++) {
            QListWidgetItem *item = m_pairListWidget->item(i);
            if (!item) continue;
            comm_pair_t *pair = (comm_pair_t *)item->data(Qt::UserRole).value<void*>();
            if (!pair) continue;

            if (rowCount % 2 == 0) {
                painter.setPen(Qt::NoPen);
                painter.setBrush(QColor(242, 242, 242));
                painter.drawRect(lx, ly, lw, rowH);
            }
            painter.setPen(Qt::black);
            tx = lx + pad;
            QString src = pair->resolved_src ? QString::fromUtf8(pair->resolved_src)
                                              : QString::fromUtf8(pair->src_addr);
            QString dst = pair->resolved_dst ? QString::fromUtf8(pair->resolved_dst)
                                              : QString::fromUtf8(pair->dst_addr);
            painter.drawText(tx, ly, cSrc,         rowH, Qt::AlignVCenter, src);  tx += cSrc;
            painter.drawText(tx, ly, cDst,         rowH, Qt::AlignVCenter, dst);  tx += cDst;
            painter.drawText(tx, ly, cPkts - pad,  rowH, Qt::AlignVCenter | Qt::AlignRight,
                             QString::number(pair->packet_count)); tx += cPkts;
            painter.drawText(tx, ly, cBytes - pad, rowH, Qt::AlignVCenter | Qt::AlignRight,
                             QString::number(pair->byte_count));
            ly += rowH;
            rowCount++;
        }
        /* Border */
        int tableEndY = ly;
        int tableStartY = ly - rowCount * rowH - hrH;
        painter.setPen(QPen(QColor(180, 180, 180), mm(0.2)));
        painter.setBrush(Qt::NoBrush);
        painter.drawRect(lx, tableStartY, lw, tableEndY - tableStartY);
    };

    /* ─────────────────────────────────────────────────────────────────
     * Helper: collect unique protocol set from visible pairs
     * ───────────────────────────────────────────────────────────────── */
    auto collectProtocols = [&]() -> QList<QPair<QString, QColor>> {
        QList<QPair<QString, QColor>> list;
        QSet<QString> seen;
        for (int i = 0; i < m_pairListWidget->count(); i++) {
            QListWidgetItem *it = m_pairListWidget->item(i);
            if (!it) continue;
            comm_pair_t *pair = (comm_pair_t *)it->data(Qt::UserRole).value<void*>();
            if (!pair || !pair->top_protocol) continue;
            QString proto = QString::fromUtf8(pair->top_protocol);
            if (!seen.contains(proto)) {
                seen.insert(proto);
                guint32 rgb = packet_analyzer_get_protocol_color(pair->top_protocol);
                /* In PDF mode darken pastel colors for readability */
                QColor c = QColor((rgb >> 16) & 0xFF, (rgb >> 8) & 0xFF, rgb & 0xFF).darker(140);
                list.append({proto, c});
            }
        }
        return list;
    };

    /* ─────────────────────────────────────────────────────────────────
     * Helper: draw protocol legend row(s) at (lx, ly) within width lw
     * Returns the y coordinate after the legend.
     * ───────────────────────────────────────────────────────────────── */
    auto drawProtocolLegend = [&](int lx, int ly, int lw) -> int {
        QList<QPair<QString, QColor>> protos = collectProtocols();
        if (protos.isEmpty()) return ly;

        QFont lf("Helvetica", 8);
        painter.setFont(lf);
        QFontMetrics lfm(lf, &writer);
        int swatchSz = lfm.height();
        int itemW    = mm(22);
        int itemH    = swatchSz + mm(1.5);
        int x = lx;
        int y = ly;

        for (const auto &pr : protos) {
            if (x + itemW > lx + lw) { x = lx; y += itemH + mm(1); }
            /* Colour swatch */
            painter.setPen(QPen(QColor(120, 120, 120), mm(0.2)));
            painter.setBrush(pr.second);
            painter.drawRect(x, y + (itemH - swatchSz) / 2, swatchSz, swatchSz);
            /* Label */
            painter.setPen(Qt::black);
            painter.drawText(x + swatchSz + mm(1), y, itemW - swatchSz - mm(1), itemH,
                             Qt::AlignVCenter, pr.first);
            x += itemW;
        }
        return y + itemH + mm(1);
    };

    /* ═══════════════════════════════════════════════════════════════════
     * PAGE 1 — COVER
     * ═══════════════════════════════════════════════════════════════════ */
    painter.fillRect(0, 0, pageW, pageH, Qt::white);

    {
        /* Logo — large, centered, upper-mid area */
        int logoH = mm(52);
        int logoY = pageH / 5;
        if (!logo.isNull()) {
            QPixmap sl = logo.scaledToHeight(logoH, Qt::SmoothTransformation);
            int logoX = (pageW - sl.width()) / 2;
            painter.drawPixmap(logoX, logoY, sl);
            logoY += logoH + mm(10);
        } else {
            logoY += mm(10);
        }

        /* Title */
        QFont titleFont("Helvetica", 40, QFont::Bold);
        painter.setFont(titleFont);
        painter.setPen(QColor(25, 25, 25));
        QFontMetrics tifm(titleFont, &writer);
        painter.drawText(0, logoY, pageW, tifm.height() + mm(2), Qt::AlignCenter, "PacketCircle Report");
        logoY += tifm.height() + mm(14);

        /* Separator */
        painter.setPen(QPen(QColor(90, 90, 90), mm(0.5)));
        int lx1 = pageW / 4, lx2 = pageW * 3 / 4;
        painter.drawLine(lx1, logoY, lx2, logoY);
        logoY += mm(12);

        /* Metadata block */
        QFont lblFont("Helvetica", 12, QFont::Bold);
        QFont valFont("Helvetica", 12);
        QFontMetrics lblfm(lblFont, &writer);
        int metaBlockW = pageW / 2;
        int metaX      = (pageW - metaBlockW) / 2;
        int lblColW    = mm(38);
        int rowH2      = lblfm.height() + mm(5);

        auto addMetaRow = [&](const QString &label, const QString &value) {
            if (value.isEmpty()) return;
            painter.setFont(lblFont);
            painter.setPen(QColor(80, 80, 80));
            painter.drawText(metaX, logoY, lblColW, rowH2, Qt::AlignVCenter | Qt::AlignRight, label + ":");
            painter.setFont(valFont);
            painter.setPen(Qt::black);
            painter.drawText(metaX + lblColW + mm(5), logoY, metaBlockW - lblColW - mm(5), rowH2,
                             Qt::AlignVCenter, value);
            logoY += rowH2;
        };

        addMetaRow("Company Name", m_reportCompany);
        addMetaRow("Prepared by",  m_reportPreparedBy);
        addMetaRow("Project",      m_reportProject);
        addMetaRow("Comments",     m_reportComments);
        addMetaRow("Date",         nowStr);

        /* GitHub URL at the very bottom */
        QFont urlFont("Helvetica", 9);
        painter.setFont(urlFont);
        painter.setPen(QColor(50, 90, 180));
        QFontMetrics ufm(urlFont, &writer);
        painter.drawText(0, pageH - ufm.height() - mm(6), pageW, ufm.height(),
                         Qt::AlignCenter, "https://github.com/netwho/PacketCircle");
    }
    drawFooter(1);

    /* ═══════════════════════════════════════════════════════════════════
     * PAGE 2 — REPORT
     * ═══════════════════════════════════════════════════════════════════ */
    writer.newPage();
    painter.fillRect(0, 0, pageW, pageH, Qt::white);
    {
        int headerY = drawPageHeader();
        int footerH = mm(10);
        int contentH = pageH - headerY - footerH;

        /* Layout: left = visualization (62%), right = pair list (36%), gap 2% */
        int listW = (int)(pageW * 0.35);
        int vizW  = pageW - listW - mm(5);
        int listX = vizW + mm(5);

        /* ── Visualization ── */
        if (currentView == 0 && m_circleWidget) {
            /* Circle view */
            int renderSz = 2000;
            QPixmap pix = m_circleWidget->renderForPDF(renderSz, renderSz);
            if (!pix.isNull()) {
                /* Reserve bottom strip for legend */
                int legendH = mm(14);
                int vizAreaH = contentH - legendH - mm(3);
                QPixmap scaled = pix.scaled(vizW, vizAreaH, Qt::KeepAspectRatio, Qt::SmoothTransformation);
                int cy = headerY + (vizAreaH - scaled.height()) / 2;
                painter.drawPixmap(0, cy, scaled);
                /* Protocol legend below circle */
                drawProtocolLegend(0, headerY + vizAreaH + mm(3), vizW);
            }
        } else if (currentView == 2 && m_graphWidget) {
            /* Graph view */
            int legendH = mm(50);  /* enough for node + edge legend rows */
            int vizAreaH = contentH - legendH - mm(3);
            QPixmap pix = m_graphWidget->renderForPDF(vizW, vizAreaH);
            if (!pix.isNull()) {
                painter.drawPixmap(0, headerY, pix);
            }

            GraphWidget::EdgeColorMode edgeCM = m_graphWidget->edgeColorMode();
            GraphWidget::NodeColorMode nodeCM = m_graphWidget->nodeColorMode();

            int ly = headerY + vizAreaH + mm(3);
            QFont lgBold("Helvetica", 7, QFont::Bold);
            QFont lgFont("Helvetica", 7);
            QFontMetrics lgfm(lgFont, &writer);
            int lrH  = lgfm.height() + mm(1.2);
            int swSz = lgfm.height();
            int swGap = mm(1);

            /* Helper: draw a row of (label, colour) swatches, wrapping if needed.
             * Returns the y position after the last row drawn. */
            auto drawSwatches = [&](int lx, int startY, int lw,
                                    const QList<QPair<QString,QColor>> &items,
                                    int itemW) -> int {
                int x = lx, y = startY;
                painter.setFont(lgFont);
                for (const auto &item : items) {
                    if (x + itemW > lx + lw) { x = lx; y += lrH; }
                    painter.setPen(QPen(QColor(110,110,110), mm(0.2)));
                    painter.setBrush(item.second);
                    painter.drawRect(x, y + (lrH - swSz) / 2, swSz, swSz);
                    painter.setPen(Qt::black);
                    painter.drawText(x + swSz + swGap, y, itemW - swSz - swGap, lrH,
                                     Qt::AlignVCenter, item.first);
                    x += itemW;
                }
                return y + lrH;
            };

            if (m_wifiMode) {
                /* ── Wi-Fi mode: cluster categories + RSSI signal quality ── */

                /* Cluster groupings (802.11 frame type) */
                painter.setFont(lgBold);
                painter.setPen(QColor(50, 50, 50));
                painter.drawText(0, ly, vizW, lrH, Qt::AlignVCenter,
                                 "Cluster — 802.11 node category:");
                ly += lrH;
                ly = drawSwatches(0, ly, vizW, {
                    {"Access Points",       QColor( 52, 152, 219)},
                    {"Management",          QColor(230, 126,  34)},
                    {"Data Stations",       QColor( 39, 174,  96)},
                    {"Broadcast/Multicast", QColor(200, 160,  64)},
                }, mm(38));

                ly += mm(2);

                /* RSSI signal quality (node + edge colour) */
                painter.setFont(lgBold);
                painter.setPen(QColor(50, 50, 50));
                painter.drawText(0, ly, vizW, lrH, Qt::AlignVCenter,
                                 "Node & edge colour — Signal quality (RSSI):");
                ly += lrH;
                {
                    const auto &wt = m_wifiThresholdGroups[m_activeWifiThresholdGroup];
                    ly = drawSwatches(0, ly, vizW, {
                        {QString("Excellent (≥ %1 dBm)").arg(wt.rssi_excellent),                        QColor(  0, 200,   0)},
                        {QString("Good      (%1..%2)")  .arg(wt.rssi_good).arg(wt.rssi_excellent - 1),  QColor(160, 220,   0)},
                        {QString("Fair      (%1..%2)")  .arg(wt.rssi_fair).arg(wt.rssi_good - 1),       QColor(255, 165,   0)},
                        {QString("Poor      (< %1 dBm)").arg(wt.rssi_fair),                             QColor(220,  50,  50)},
                        {"No signal",                                                                    QColor(160, 160, 160)},
                    }, mm(40));
                }

            } else {
                /* ── Normal mode: node colour + edge colour sections ── */

                /* Node colour section */
                {
                    QString modeLabel;
                    switch (nodeCM) {
                        case GraphWidget::NODECOLOR_SERVICE:  modeLabel = "Node colour — Service / Port:"; break;
                        case GraphWidget::NODECOLOR_ROLE:     modeLabel = "Node colour — Host Role:";      break;
                        case GraphWidget::NODECOLOR_PROTOCOL: modeLabel = "Node colour — Protocol:";       break;
                        case GraphWidget::NODECOLOR_FUNCTION: modeLabel = "Node colour — Function:";       break;
                    }
                    painter.setFont(lgBold);
                    painter.setPen(QColor(50, 50, 50));
                    painter.drawText(0, ly, vizW, lrH, Qt::AlignVCenter, modeLabel);
                    ly += lrH;

                    switch (nodeCM) {
                        case GraphWidget::NODECOLOR_SERVICE: {
                            auto services = m_graphWidget->legendServicesForPDF();
                            if (services.isEmpty()) {
                                painter.setFont(lgFont); painter.setPen(Qt::black);
                                painter.drawText(0, ly, vizW, lrH, Qt::AlignVCenter, "(no named services in current data)");
                                ly += lrH;
                            } else {
                                ly = drawSwatches(0, ly, vizW, services, mm(22));
                            }
                            break;
                        }
                        case GraphWidget::NODECOLOR_ROLE: {
                            QList<QPair<QString,QColor>> roles = {
                                {"Internal (RFC1918)", QColor(41,  98, 163)},
                                {"External (Public)",  QColor(180, 55,  35)},
                                {"Broadcast/Multicast",QColor(160,110,  10)},
                                {"MAC address",        QColor(110, 55, 155)},
                            };
                            ly = drawSwatches(0, ly, vizW, roles, mm(34));
                            break;
                        }
                        case GraphWidget::NODECOLOR_PROTOCOL: {
                            ly = drawSwatches(0, ly, vizW, collectProtocols(), mm(22));
                            break;
                        }
                        case GraphWidget::NODECOLOR_FUNCTION: {
                            QList<QPair<QString,QColor>> fns = {
                                {"Remote (RDP/VNC/Citrix)",    QColor(180, 30, 30)},
                                {"Interactive (SSH/Telnet)",   QColor(210,100, 10)},
                                {"Messaging (SIP/XMPP/IRC)",   QColor( 15,155,130)},
                                {"Filetransfer (SMB/NFS/FTP)", QColor( 30,155, 65)},
                                {"Other / uncategorised",      QColor(150,150,150)},
                            };
                            ly = drawSwatches(0, ly, vizW, fns, mm(34));
                            break;
                        }
                    }
                }

                ly += mm(2);

                /* Edge colour section */
                {
                    QString modeLabel;
                    switch (edgeCM) {
                        case GraphWidget::COLOR_PROTOCOL:
                            modeLabel = "Edge colour — Protocol:"; break;
                        case GraphWidget::COLOR_TCP_HEALTH:
                            modeLabel = "Edge colour — TCP Health Score:"; break;
                        case GraphWidget::COLOR_ANOMALY:
                            modeLabel = "Edge colour — Anomaly Score:"; break;
                        case GraphWidget::COLOR_RESPONSE_TIME:
                            modeLabel = "Edge colour — Response Time:"; break;
                        case GraphWidget::COLOR_THROUGHPUT:
                            modeLabel = "Edge colour — Throughput:"; break;
                        case GraphWidget::COLOR_HIGH_RISK:
                            modeLabel = "Edge colour — High Risk:"; break;
                        case GraphWidget::COLOR_TCP_WINDOW:
                            modeLabel = "Edge colour — TCP Window:"; break;
                    }
                    painter.setFont(lgBold);
                    painter.setPen(QColor(50, 50, 50));
                    painter.drawText(0, ly, vizW, lrH, Qt::AlignVCenter, modeLabel);
                    ly += lrH;

                    switch (edgeCM) {
                        case GraphWidget::COLOR_PROTOCOL:
                            ly = drawSwatches(0, ly, vizW, collectProtocols(), mm(22));
                            break;
                        case GraphWidget::COLOR_TCP_HEALTH:
                            ly = drawSwatches(0, ly, vizW, {
                                {"Healthy (≥0.75)",   QColor( 39,174, 96)},
                                {"Moderate (≥0.50)",  QColor(241,196, 15)},
                                {"Degraded (≥0.28)",  QColor(230,126, 34)},
                                {"Unhealthy (<0.28)", QColor(231, 76, 60)},
                            }, mm(30));
                            break;
                        case GraphWidget::COLOR_ANOMALY:
                            ly = drawSwatches(0, ly, vizW, {
                                {"Clean (≤0.12)",       QColor( 39,174, 96)},
                                {"Noteworthy (≤0.30)",  QColor(241,196, 15)},
                                {"Suspicious (≤0.55)",  QColor(230,126, 34)},
                                {"Anomalous (>0.55)",   QColor(231, 76, 60)},
                            }, mm(32));
                            break;
                        case GraphWidget::COLOR_RESPONSE_TIME:
                            ly = drawSwatches(0, ly, vizW, {
                                {"Unavailable",    QColor(160,160,160)},
                                {"Fast",           QColor( 39,174, 96)},
                                {"Moderate",       QColor(130,200, 60)},
                                {"Slow",           QColor(241,196, 15)},
                                {"Very slow",      QColor(230,126, 34)},
                                {"Unacceptable",   QColor(231, 76, 60)},
                            }, mm(26));
                            break;
                        case GraphWidget::COLOR_THROUGHPUT:
                            ly = drawSwatches(0, ly, vizW, {
                                {"Unknown",        QColor(160,160,160)},
                                {"<10 KB/s",       QColor( 52,152,219)},
                                {"10–100 KB/s",    QColor( 39,174, 96)},
                                {"100 KB–1 MB/s",  QColor(241,196, 15)},
                                {"1–10 MB/s",      QColor(230,126, 34)},
                                {">10 MB/s",       QColor(231, 76, 60)},
                            }, mm(26));
                            break;
                        case GraphWidget::COLOR_HIGH_RISK:
                            ly = drawSwatches(0, ly, vizW, {
                                {"Critical (Telnet/VNC/FTP/X11)", QColor(185, 20, 20)},
                                {"VPN / TOR",                     QColor(120, 50,175)},
                                {"High (RDP / WinRM)",            QColor(205, 80, 10)},
                                {"Elevated (SSH / SNMP)",         QColor(185,150, 10)},
                                {"Normal",                        QColor(140,140,140)},
                            }, mm(26));
                            break;
                        case GraphWidget::COLOR_TCP_WINDOW:
                            ly = drawSwatches(0, ly, vizW, {
                                {"No stall  (>= 32 KB)", QColor( 39,174, 96)},
                                {"Mild      (8-32 KB)",  QColor(130,200, 60)},
                                {"Moderate  (4-8 KB)",   QColor(241,196, 15)},
                                {"Constrained (< 4 KB)", QColor(230,126, 34)},
                                {"Zero-window stall",    QColor(231, 76, 60)},
                            }, mm(30));
                            break;
                    }
                }
            }

            ly += mm(2);

            /* ── Edge thickness (always) ── */
            painter.setFont(lgFont);
            painter.setPen(QPen(QColor(80,80,80), mm(0.4)));
            painter.drawLine(0,     ly + lrH/2, mm(10), ly + lrH/2);
            painter.setPen(QPen(QColor(80,80,80), mm(2.0)));
            painter.drawLine(mm(12),ly + lrH/2, mm(26), ly + lrH/2);
            painter.setPen(Qt::black);
            painter.drawText(mm(28), ly, vizW - mm(28), lrH, Qt::AlignVCenter,
                             "Edge thickness: relative traffic volume");
            ly += lrH;
            Q_UNUSED(ly);
        } else {
            /* Table view — render the connection table in the left area */
            int legendH = mm(14);
            int vizAreaH = contentH - legendH - mm(3);

            QFont thf("Helvetica", 8, QFont::Bold);
            QFont tf("Courier", 7);
            QFontMetrics thfm(thf, &writer);
            QFontMetrics tfm(tf, &writer);
            int rowH = tfm.height() + mm(1.2);

            int pad = mm(1);
            int uw  = vizW - 2 * pad;
            int cSrc  = (int)(uw * 0.25);
            int cDst  = (int)(uw * 0.25);
            int cProto = mm(20);
            int cTrans = mm(16);
            int cPkts = (int)(uw * 0.14);
            int cBytes = uw - cSrc - cDst - cProto - cTrans - cPkts;

            int ty = headerY;
            /* Header */
            int hrH = thfm.height() + mm(1.8);
            painter.setPen(Qt::NoPen);
            painter.setBrush(QColor(55, 55, 55));
            painter.drawRect(0, ty, vizW, hrH);
            painter.setFont(thf);
            painter.setPen(Qt::white);
            int tx = pad;
            int tvc = ty + (hrH - thfm.height()) / 2;
            painter.drawText(tx, tvc, cSrc,  hrH, Qt::AlignVCenter, "Source");   tx += cSrc;
            painter.drawText(tx, tvc, cDst,  hrH, Qt::AlignVCenter, "Destination"); tx += cDst;
            painter.drawText(tx, tvc, cProto,hrH, Qt::AlignVCenter, "Protocol"); tx += cProto;
            painter.drawText(tx, tvc, cTrans,hrH, Qt::AlignVCenter, "Transport"); tx += cTrans;
            painter.drawText(tx, tvc, cPkts - pad, hrH, Qt::AlignVCenter | Qt::AlignRight, "Packets"); tx += cPkts;
            painter.drawText(tx, tvc, cBytes - pad,hrH, Qt::AlignVCenter | Qt::AlignRight, "Bytes");
            ty += hrH;

            /* Data rows */
            painter.setFont(tf);
            int rowCount = 0;
            int maxRows  = (vizAreaH - hrH) / rowH;
            for (int i = 0; i < m_pairListWidget->count() && rowCount < maxRows; i++) {
                QListWidgetItem *it = m_pairListWidget->item(i);
                if (!it) continue;
                comm_pair_t *pair = (comm_pair_t *)it->data(Qt::UserRole).value<void*>();
                if (!pair) continue;

                if (rowCount % 2 == 0) {
                    painter.setPen(Qt::NoPen);
                    painter.setBrush(QColor(242, 242, 242));
                    painter.drawRect(0, ty, vizW, rowH);
                }
                painter.setPen(Qt::black);
                tx = pad;
                QString src = pair->resolved_src ? QString::fromUtf8(pair->resolved_src)
                                                  : QString::fromUtf8(pair->src_addr);
                QString dst = pair->resolved_dst ? QString::fromUtf8(pair->resolved_dst)
                                                  : QString::fromUtf8(pair->dst_addr);
                QString proto = pair->top_protocol ? QString::fromUtf8(pair->top_protocol) : "—";
                bool hasTcp = false, hasUdp = false;
                if (pair->dst_ports) {
                    GHashTableIter it2; gpointer k, v;
                    g_hash_table_iter_init(&it2, pair->dst_ports);
                    while (g_hash_table_iter_next(&it2, &k, &v)) {
                        port_stats_t *ps = (port_stats_t *)v;
                        if (ps) { hasTcp |= (ps->is_tcp == TRUE); hasUdp |= (ps->is_udp == TRUE); }
                    }
                }
                QString transport = hasTcp && hasUdp ? "TCP+UDP" : hasTcp ? "TCP" : hasUdp ? "UDP" : "—";
                painter.drawText(tx, ty, cSrc,         rowH, Qt::AlignVCenter, src);    tx += cSrc;
                painter.drawText(tx, ty, cDst,         rowH, Qt::AlignVCenter, dst);    tx += cDst;
                painter.drawText(tx, ty, cProto,       rowH, Qt::AlignVCenter, proto);  tx += cProto;
                painter.drawText(tx, ty, cTrans,       rowH, Qt::AlignVCenter, transport); tx += cTrans;
                painter.drawText(tx, ty, cPkts - pad,  rowH, Qt::AlignVCenter | Qt::AlignRight,
                                 QString::number(pair->packet_count)); tx += cPkts;
                painter.drawText(tx, ty, cBytes - pad, rowH, Qt::AlignVCenter | Qt::AlignRight,
                                 QString::number(pair->byte_count));
                ty += rowH;
                rowCount++;
            }
            painter.setPen(QPen(QColor(180, 180, 180), mm(0.2)));
            painter.setBrush(Qt::NoBrush);
            painter.drawRect(0, headerY, vizW, ty - headerY);

            /* Protocol legend */
            drawProtocolLegend(0, headerY + vizAreaH + mm(3), vizW);
        }

        /* ── Pair list (right column) ── */
        drawPairList(listX, headerY, listW, contentH);

        /* ── "Comm Pair List" label above the pair list ── */
        {
            QFont lblFont("Helvetica", 8, QFont::Bold);
            painter.setFont(lblFont);
            painter.setPen(QColor(70, 70, 70));
            QFontMetrics lblfm(lblFont, &writer);
            /* Draw it just above the list — headerY is where the list starts, label fits in the small gap */
            painter.drawText(listX, headerY - lblfm.height() - mm(1), listW, lblfm.height(),
                             Qt::AlignHCenter, "Communication Pairs");
        }
    }
    drawFooter(2);

    /* ═══════════════════════════════════════════════════════════════════
     * PAGE 3 — EXPLANATION
     * ═══════════════════════════════════════════════════════════════════ */
    writer.newPage();
    painter.fillRect(0, 0, pageW, pageH, Qt::white);
    {
        int y = drawPageHeader();

        QFont h1Font("Helvetica", 14, QFont::Bold);
        QFont h2Font("Helvetica", 10, QFont::Bold);
        QFont bodyFont("Helvetica", 9);

        auto drawH1 = [&](const QString &text) {
            painter.setFont(h1Font);
            painter.setPen(QColor(30, 30, 30));
            QFontMetrics fm(h1Font, &writer);
            painter.drawText(0, y, pageW, fm.height() + mm(1), Qt::AlignLeft, text);
            y += fm.height() + mm(3);
            painter.setPen(QPen(QColor(160, 160, 160), mm(0.3)));
            painter.drawLine(0, y - mm(1), pageW, y - mm(1));
            y += mm(2);
        };

        auto drawH2 = [&](const QString &text) {
            painter.setFont(h2Font);
            painter.setPen(QColor(40, 80, 130));
            QFontMetrics fm(h2Font, &writer);
            y += mm(3);
            painter.drawText(0, y, pageW, fm.height(), Qt::AlignLeft, text);
            y += fm.height() + mm(2);
        };

        auto drawBody = [&](const QString &text) {
            painter.setFont(bodyFont);
            painter.setPen(Qt::black);
            QRect r(0, y, pageW, pageH - y - mm(15));
            QRect bound;
            painter.drawText(r, Qt::AlignLeft | Qt::TextWordWrap, text, &bound);
            y = bound.bottom() + mm(2);
        };

        auto drawBullet = [&](const QString &text) {
            drawBody("\u2022  " + text);
        };

        /* ─── General section ─── */
        drawH1("About This Report");

        drawBody(QString(
            "This PacketCircle report was generated on %1 and captures the state of the "
            "analysis at the time the PDF button was clicked. It shows the top %2 communication "
            "pairs ranked by %3, extracted from the currently active Wireshark capture. "
            "Any Wireshark display filter in effect at the time of generation is reflected in the data.")
            .arg(nowStr)
            .arg(m_topN)
            .arg(m_useBytes ? "byte volume" : "packet count"));

        /* ─── View-specific section ─── */
        if (currentView == 0) {
            /* Circle view */
            drawH2("Circle View — How to Read It");
            drawBody("The circle diagram on page 2 places each network endpoint (host or MAC address) "
                     "as a node on a circle. A line between two nodes indicates that communication was "
                     "observed between those hosts in the captured traffic.");
            drawBullet("Line colour indicates the dominant application-layer protocol of that flow "
                       "(e.g. TCP = light green, UDP = pastel orange, ARP = sky blue, ICMP = pale turquoise). "
                       "When both TCP and UDP are present on the same pair the line is drawn with a "
                       "dashed alternating pattern.");
            drawBullet("Line thickness (when enabled) is proportional to the traffic volume — "
                       "thicker lines carry more packets or bytes relative to the other pairs shown.");
            drawBullet("Node colour reflects the dominant protocol of all connections for that host.");
            drawBullet("Node labels show the IP address or resolved hostname. Hover in the live UI "
                       "to highlight all connections for that host.");
        } else if (currentView == 2) {
            /* Graph view */
            drawH2("Graph View — How to Read It");
            drawBody("The force-directed graph on page 2 arranges hosts as nodes with edges "
                     "representing observed communication. Unlike the circle view the layout is "
                     "computed by a physics simulation that pulls heavily connected nodes together "
                     "and pushes unrelated nodes apart, revealing clusters of related infrastructure.");
            drawBullet("Node colour encodes the selected node colour mode: Service / Port assigns "
                       "a distinct colour per well-known service (HTTPS, SSH, DNS, …); Role "
                       "distinguishes internal RFC1918 hosts from external public addresses; "
                       "Protocol uses the same palette as the Circle view.");
            drawBullet("Edge thickness reflects the relative volume of traffic on that link. "
                       "Thin edges carry little traffic; thick edges are high-volume flows.");
            drawBullet("Anomaly scoring evaluates each connection against configurable thresholds "
                       "for packet rate, byte volume, connection duration, protocol mix, and port "
                       "count. High anomaly scores (warmer colours) may indicate port scans, "
                       "data exfiltration, or malfunctioning applications.");

            drawH2("Graph Threshold Groups");
            drawBody("Three built-in threshold profiles are provided: Default (balanced), "
                     "Strict (flags more connections as anomalous), and Tolerant (only flags "
                     "extreme outliers). Custom groups can be created in Settings → Graph Thresholds. "
                     "The active group at report time was: " +
                     (m_activeThresholdGroup >= 0 && m_activeThresholdGroup < m_thresholdGroups.size()
                         ? m_thresholdGroups[m_activeThresholdGroup].name
                         : QString("Default")) + ".");
        } else {
            /* Table view */
            drawH2("Table View — How to Read It");
            drawBody("The connection table on page 2 lists each directional communication pair "
                     "as a separate row, sorted by the selected metric (packets or bytes). "
                     "Each row represents all traffic observed from one host to another.");
            drawBullet("Source / Destination: the IP address or resolved hostname of each endpoint. "
                       "Resolved names come from Wireshark's name resolution settings.");
            drawBullet("Protocol: the dominant application-layer protocol for that pair, "
                       "determined by the highest-frequency port and the Wireshark dissector match.");
            drawBullet("Transport: TCP, UDP, or TCP+UDP when both were seen on the same host pair.");
            drawBullet("Packets / Bytes: total counts in the direction Source → Destination.");
            drawBullet("Right-click any row in the live UI to apply a Wireshark display filter, "
                       "follow a TCP stream, open protocol info dialogs, or view transport statistics.");
        }

        /* ─── Common section ─── */
        drawH2("Communication Pair List (Right Column)");
        drawBody("The pair list on the right side of page 2 shows all pairs in the same order "
                 "as the main view. Each entry is labelled src \u2192 dst with the top protocol "
                 "and total packet count. Use this as a quick reference index when correlating "
                 "the visual with specific host pairs.");

        drawH2("Filters and Scope");
        drawBullet(QString("Top-N setting at report time: Top %1 pairs.").arg(m_topN));
        drawBullet(QString("Metric: ranked by %1.").arg(m_useBytes ? "byte volume" : "packet count"));
        drawBullet(QString("Mode: %1.").arg(m_useMAC ? "MAC / Layer-2 mode" : "IP / Layer-3 mode"));
        drawBody("If a Wireshark display filter was active when the PDF was generated, only packets "
                 "matching that filter are reflected in the counts shown. To regenerate with the "
                 "full capture, clear the filter, click Reload, then click PDF again.");

        /* ─── Footer note ─── */
        QFont noteFont("Helvetica", 7);
        painter.setFont(noteFont);
        painter.setPen(QColor(130, 130, 130));
        painter.drawText(0, pageH - mm(20), pageW, mm(10), Qt::AlignCenter | Qt::TextWordWrap,
                         "PacketCircle is a free open-source Wireshark plugin. "
                         "Source code and latest release: https://github.com/netwho/PacketCircle");
    }
    drawFooter(3);

    painter.end();

    QMessageBox::information(this, "PDF Saved", QString("Report saved to:\n%1").arg(filePath));
}

/* ------------------------------------------------------------------ */
/* ntopng integration                                                   */
/* ------------------------------------------------------------------ */

bool MainWindow::showNtopngConfigDialog()
{
    QDialog dlg(this);
    dlg.setWindowTitle("ntopng Settings");
    dlg.setMinimumWidth(400);

    QSettings settings(preferencesFilePath(), QSettings::IniFormat);
    settings.beginGroup("ntopng");

    QFormLayout *form = new QFormLayout;

    QLineEdit *hostEdit = new QLineEdit(settings.value("host", "").toString());
    hostEdit->setPlaceholderText("e.g. ntop.example.com or 192.168.1.10");

    QLineEdit *portEdit = new QLineEdit(QString::number(settings.value("port", 3001).toInt()));
    portEdit->setInputMask("99999");

    QCheckBox *httpsBox = new QCheckBox("Use HTTPS");
    httpsBox->setChecked(settings.value("use_https", true).toBool());

    QLineEdit *userEdit = new QLineEdit(settings.value("username", "").toString());

    QLineEdit *passEdit = new QLineEdit(settings.value("password", "").toString());
    passEdit->setEchoMode(QLineEdit::Password);

    QCheckBox *ignoreSslBox = new QCheckBox("Ignore SSL certificate errors (self-signed / internal CA)");
    ignoreSslBox->setChecked(settings.value("ignore_ssl_errors", true).toBool());

    settings.endGroup();

    form->addRow("Host:", hostEdit);
    form->addRow("Port:", portEdit);
    form->addRow("", httpsBox);
    form->addRow("Username:", userEdit);
    form->addRow("Password:", passEdit);
    form->addRow("", ignoreSslBox);

    QDialogButtonBox *buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
    connect(buttons, &QDialogButtonBox::accepted, &dlg, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);

    QVBoxLayout *vbox = new QVBoxLayout(&dlg);
    vbox->addLayout(form);
    vbox->addWidget(buttons);

    if (dlg.exec() != QDialog::Accepted)
        return false;

    QString host = hostEdit->text().trimmed();
    int port = portEdit->text().trimmed().toInt();
    if (port <= 0 || port > 65535) port = 3001;

    settings.beginGroup("ntopng");
    settings.setValue("host", host);
    settings.setValue("port", port);
    settings.setValue("use_https", httpsBox->isChecked());
    settings.setValue("username", userEdit->text().trimmed());
    settings.setValue("password", passEdit->text());
    settings.setValue("ignore_ssl_errors", ignoreSslBox->isChecked());
    settings.endGroup();
    settings.sync();
    return true;
}

/* ── CA Certificate dialog ──────────────────────────────────────────────── */
void MainWindow::showCaCertConfigDialog()
{
    bool dark = isDarkTheme();
    QDialog dlg(this);
    dlg.setWindowTitle("Local CA Certificate");
    dlg.setMinimumWidth(480);

    if (dark) {
        dlg.setStyleSheet(
            "QDialog { background:#1e1e1e; color:#e0e0e0; }"
            "QLabel  { color:#e0e0e0; }"
            "QLineEdit { background:#2b2b2b; color:#e0e0e0; border:1px solid #555; padding:3px; border-radius:3px; }"
            "QPushButton { background:#333; color:#e0e0e0; border:1px solid #555; padding:4px 12px; border-radius:3px; }"
            "QPushButton:hover { background:#444; }"
        );
    }

    QSettings settings(preferencesFilePath(), QSettings::IniFormat);
    settings.beginGroup("ntopng");
    QString current = settings.value("ca_cert_path", "").toString();
    settings.endGroup();

    QFormLayout *form = new QFormLayout;
    QLineEdit *certEdit = new QLineEdit(current);
    certEdit->setPlaceholderText("Optional — leave blank to use system trust store");
    certEdit->setMinimumWidth(300);

    QPushButton *browseBtn = new QPushButton("Browse\u2026");
    QHBoxLayout *row = new QHBoxLayout;
    row->addWidget(certEdit);
    row->addWidget(browseBtn);
    connect(browseBtn, &QPushButton::clicked, &dlg, [&dlg, certEdit]() {
        QString path = QFileDialog::getOpenFileName(&dlg, "Select CA Certificate",
            QString(), "Certificates (*.pem *.crt *.cer);;All files (*)");
        if (!path.isEmpty())
            certEdit->setText(path);
    });

    QLabel *note = new QLabel(
        "Used when connecting to ntopng with a custom or self-signed CA.\n"
        "Leave blank to rely on the system trust store.");
    note->setWordWrap(true);
    if (dark) note->setStyleSheet("color:#aaa;font-size:11px;");
    else      note->setStyleSheet("color:#555;font-size:11px;");

    QDialogButtonBox *buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
    connect(buttons, &QDialogButtonBox::accepted, &dlg, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);

    QVBoxLayout *vbox = new QVBoxLayout(&dlg);
    form->addRow("CA Certificate:", row);
    vbox->addLayout(form);
    vbox->addWidget(note);
    vbox->addSpacing(6);
    vbox->addWidget(buttons);

    if (dlg.exec() != QDialog::Accepted) return;

    settings.beginGroup("ntopng");
    settings.setValue("ca_cert_path", certEdit->text().trimmed());
    settings.endGroup();
    settings.sync();
}

/* ── Report configuration dialog ────────────────────────────────────────── */
void MainWindow::showReportConfigDialog()
{
    bool dark = isDarkTheme();
    QDialog dlg(this);
    dlg.setWindowTitle("Configure Reports");
    dlg.setMinimumWidth(420);

    if (dark) {
        dlg.setStyleSheet(
            "QDialog { background:#1e1e1e; color:#e0e0e0; }"
            "QLabel  { color:#e0e0e0; }"
            "QLineEdit { background:#2a2a2a; color:#e0e0e0; border:1px solid #555; padding:3px; border-radius:3px; }"
            "QComboBox { background:#2a2a2a; color:#e0e0e0; border:1px solid #555; padding:3px; border-radius:3px; }"
            "QPushButton { background:#333; color:#e0e0e0; border:1px solid #555; padding:4px 14px; border-radius:3px; }"
            "QPushButton:hover { background:#444; }"
        );
    }

    QVBoxLayout *main = new QVBoxLayout(&dlg);
    main->setSpacing(10);
    main->setContentsMargins(14, 12, 14, 12);

    QFormLayout *form = new QFormLayout;
    form->setLabelAlignment(Qt::AlignRight | Qt::AlignVCenter);
    form->setHorizontalSpacing(12);
    form->setVerticalSpacing(8);

    QLineEdit *companyEdit     = new QLineEdit(m_reportCompany);
    QLineEdit *preparedByEdit  = new QLineEdit(m_reportPreparedBy);
    QLineEdit *projectEdit     = new QLineEdit(m_reportProject);
    QLineEdit *commentsEdit    = new QLineEdit(m_reportComments);
    companyEdit->setPlaceholderText("e.g. Acme Corp");
    preparedByEdit->setPlaceholderText("e.g. Jane Smith");
    projectEdit->setPlaceholderText("e.g. Q2 Security Audit (optional)");
    commentsEdit->setPlaceholderText("e.g. Demo Segment Analysis");

    QComboBox *paperCombo = new QComboBox;
    paperCombo->addItem("A4  (210 \u00d7 297 mm)");
    paperCombo->addItem("Legal  (8.5 \u00d7 14 in)");
    paperCombo->setCurrentIndex(m_reportPaperSize);

    form->addRow("Company Name:", companyEdit);
    form->addRow("Prepared by:", preparedByEdit);
    form->addRow("Project:", projectEdit);
    form->addRow("Comments:", commentsEdit);
    form->addRow("Paper Size:", paperCombo);

    main->addLayout(form);
    main->addStretch();

    QDialogButtonBox *buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
    connect(buttons, &QDialogButtonBox::accepted, &dlg, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);
    main->addWidget(buttons);

    if (dlg.exec() == QDialog::Accepted) {
        m_reportCompany    = companyEdit->text().trimmed();
        m_reportPreparedBy = preparedByEdit->text().trimmed();
        m_reportProject    = projectEdit->text().trimmed();
        m_reportComments   = commentsEdit->text().trimmed();
        m_reportPaperSize  = paperCombo->currentIndex();
        savePreferences();
    }
}

/* ── Settings dialog ─────────────────────────────────────────────────────────
 * Single unified window: section selector (QComboBox) at top, QStackedWidget
 * in the middle, Reset All + Close at the bottom.  Window auto-resizes when
 * the user switches sections.                                                */
void MainWindow::showSettingsDialog(int initialPage)
{
    bool dark = isDarkTheme();
    QDialog dlg(this);
    dlg.setWindowTitle(QString("PacketCircle Settings  —  %1").arg(QLatin1String(PC_VERSION)));
    dlg.setSizeGripEnabled(true);

    const QString ss = dark ?
        "QDialog  { background:#1e1e1e; color:#e0e0e0; }"
        "QLabel   { color:#e0e0e0; }"
        "QGroupBox{ color:#e0e0e0; border:1px solid #444; border-radius:4px; margin-top:8px; }"
        "QGroupBox::title{ subcontrol-origin:margin; left:10px; padding:0 4px; color:#90caf9; }"
        "QCheckBox{ color:#e0e0e0; }"
        "QListWidget{ background:#2a2a2a; color:#e0e0e0; border:1px solid #444; }"
        "QLineEdit{ background:#2a2a2a; color:#e0e0e0; border:1px solid #555; padding:2px; border-radius:3px; }"
        "QSpinBox { background:#2a2a2a; color:#e0e0e0; border:1px solid #555; }"
        "QComboBox{ background:#2a2a2a; color:#e0e0e0; border:1px solid #555; padding:2px; }"
        "QPushButton{ background:#333; color:#e0e0e0; border:1px solid #555; padding:4px 14px; border-radius:3px; }"
        "QPushButton:hover:enabled{ background:#444; }"
        "QPushButton:disabled{ color:#555; border-color:#444; background:#2a2a2a; }"
        : "";
    if (dark) dlg.setStyleSheet(ss);

    QVBoxLayout *outerLayout = new QVBoxLayout(&dlg);
    outerLayout->setSpacing(8);
    outerLayout->setContentsMargins(14, 10, 14, 10);

    /* ── Section selector ─────────────────────────────────────────────── */
    QComboBox *sectionCombo = new QComboBox;
    sectionCombo->addItem("Integration");
    sectionCombo->addItem("Internal Networks");
    sectionCombo->addItem("Performance");
    sectionCombo->addItem("Graph Thresholds");
    sectionCombo->addItem("Wi-Fi Thresholds");
    sectionCombo->addItem("Reports");
    sectionCombo->addItem("About");
    outerLayout->addWidget(sectionCombo);

    /* ── Stacked pages ────────────────────────────────────────────────── */
    QStackedWidget *stack = new QStackedWidget;
    outerLayout->addWidget(stack);

    /* ── PAGE 0 — Integration ─────────────────────────────────────────── */
    {
        QWidget *page = new QWidget;
        QVBoxLayout *pv = new QVBoxLayout(page);
        pv->setSpacing(8); pv->setContentsMargins(0,4,0,4);

        QGroupBox *intGrp = new QGroupBox("Integrations");
        QVBoxLayout *intBox = new QVBoxLayout(intGrp);
        intBox->setSpacing(6);

        /* ntopng row */
        QCheckBox *ntopChk = new QCheckBox("ntopng");
        ntopChk->setChecked(m_ntopEnabled);
        QPushButton *cfgNtopBtn = new QPushButton("Configure…");
        cfgNtopBtn->setEnabled(m_ntopEnabled);
        QHBoxLayout *ntopRow = new QHBoxLayout;
        ntopRow->addWidget(ntopChk, 1);
        ntopRow->addWidget(cfgNtopBtn);
        intBox->addLayout(ntopRow);

        /* CA Certificate — own separate row */
        QLabel *certLbl = new QLabel("CA Certificate:");
        QPushButton *cfgCertBtn = new QPushButton("Configure…");
        cfgCertBtn->setToolTip("Set a custom CA certificate for TLS connections");
        QHBoxLayout *certRow = new QHBoxLayout;
        certRow->addWidget(certLbl, 1);
        certRow->addWidget(cfgCertBtn);
        intBox->addLayout(certRow);

        /* Malcolm row */
        QCheckBox *malcolmChk = new QCheckBox("Malcolm / Arkime");
        malcolmChk->setChecked(m_malcolmEnabled);
        QPushButton *cfgMalcolmBtn = new QPushButton("Configure…");
        cfgMalcolmBtn->setEnabled(m_malcolmEnabled);
        QHBoxLayout *malcolmRow = new QHBoxLayout;
        malcolmRow->addWidget(malcolmChk, 1);
        malcolmRow->addWidget(cfgMalcolmBtn);
        intBox->addLayout(malcolmRow);

        pv->addWidget(intGrp);
        pv->addStretch();

        QObject::connect(ntopChk, &QCheckBox::toggled, [this, cfgNtopBtn](bool on) {
            cfgNtopBtn->setEnabled(on);
            m_ntopEnabled = on;
            if (m_sendToNtopBtn) m_sendToNtopBtn->setVisible(on);
        });
        QObject::connect(cfgNtopBtn,    &QPushButton::clicked, this, &MainWindow::showNtopngConfigDialog);
        QObject::connect(cfgCertBtn,    &QPushButton::clicked, this, &MainWindow::showCaCertConfigDialog);
        QObject::connect(malcolmChk, &QCheckBox::toggled, [this, cfgMalcolmBtn](bool on) {
            cfgMalcolmBtn->setEnabled(on);
            m_malcolmEnabled = on;
            if (m_sendToMalcolmBtn) m_sendToMalcolmBtn->setVisible(on);
        });
        QObject::connect(cfgMalcolmBtn, &QPushButton::clicked, this, &MainWindow::showMalcolmConfigDialog);

        stack->addWidget(page);
    }

    /* ── PAGE 1 — Internal Networks ───────────────────────────────────── */
    {
        QWidget *page = new QWidget;
        QVBoxLayout *pv = new QVBoxLayout(page);
        pv->setSpacing(8); pv->setContentsMargins(0,4,0,4);

        QGroupBox *netGrp = new QGroupBox("Internal Networks (Graph)");
        QVBoxLayout *netBox = new QVBoxLayout(netGrp);
        netBox->setSpacing(6);

        QLabel *netNote = new QLabel("Subnets treated as Internal in cluster view. Change /bits to adjust granularity.");
        netNote->setWordWrap(true);
        netBox->addWidget(netNote);

        QListWidget *snList = new QListWidget;
        snList->setFixedHeight(100);
        snList->setSelectionMode(QAbstractItemView::SingleSelection);
        auto rebuildSnList = [this, snList]() {
            snList->clear();
            for (const auto &sn : m_internalSubnets)
                snList->addItem(QString("%1/%2%3").arg(sn.prefix).arg(sn.bits)
                                .arg(sn.builtIn ? " (built-in)" : ""));
        };
        rebuildSnList();
        netBox->addWidget(snList);

        QHBoxLayout *snAddRow = new QHBoxLayout;
        QLineEdit *snIpEdit = new QLineEdit;
        snIpEdit->setPlaceholderText("IP prefix (e.g. 10.5.0.0)");
        QLabel *snSlash = new QLabel("/");
        QSpinBox *snBits = new QSpinBox;
        snBits->setRange(1, 32); snBits->setValue(24);
        QPushButton *snAddBtn = new QPushButton("Add");
        snAddRow->addWidget(snIpEdit, 1);
        snAddRow->addWidget(snSlash);
        snAddRow->addWidget(snBits);
        snAddRow->addWidget(snAddBtn);
        netBox->addLayout(snAddRow);

        QPushButton *snRemoveBtn  = new QPushButton("Remove Selected");
        QPushButton *snSetBitsBtn = new QPushButton("Set /bits for selected");
        snRemoveBtn->setEnabled(false);
        snSetBitsBtn->setEnabled(false);
        snSetBitsBtn->setToolTip("Update the clustering prefix length for the selected subnet");
        QHBoxLayout *snBtnRow2 = new QHBoxLayout;
        snBtnRow2->addWidget(snRemoveBtn);
        snBtnRow2->addWidget(snSetBitsBtn);
        netBox->addLayout(snBtnRow2);

        QObject::connect(snList, &QListWidget::currentRowChanged, [this, snList, snBits, snRemoveBtn, snSetBitsBtn](int row) {
            bool valid = (row >= 0 && row < (int)m_internalSubnets.size());
            snRemoveBtn->setEnabled(valid && !m_internalSubnets[row].builtIn);
            snSetBitsBtn->setEnabled(valid);
            if (valid) snBits->setValue(m_internalSubnets[row].bits);
        });
        QObject::connect(snSetBitsBtn, &QPushButton::clicked, [this, snList, snBits, rebuildSnList]() {
            int row = snList->currentRow();
            if (row < 0 || row >= (int)m_internalSubnets.size()) return;
            m_internalSubnets[row].bits = snBits->value();
            rebuildSnList();
            snList->setCurrentRow(row);
            if (m_graphWidget) m_graphWidget->setInternalSubnets(m_internalSubnets);
        });
        QObject::connect(snAddBtn, &QPushButton::clicked, [this, snIpEdit, snBits, rebuildSnList]() {
            QString prefix = snIpEdit->text().trimmed();
            if (prefix.isEmpty()) return;
            GraphWidget::InternalSubnet sn;
            sn.prefix = prefix; sn.bits = snBits->value(); sn.builtIn = false;
            m_internalSubnets.append(sn);
            rebuildSnList();
            snIpEdit->clear();
            if (m_graphWidget) m_graphWidget->setInternalSubnets(m_internalSubnets);
        });
        QObject::connect(snRemoveBtn, &QPushButton::clicked, [this, snList, snRemoveBtn, snSetBitsBtn, rebuildSnList]() {
            int row = snList->currentRow();
            if (row < 0 || row >= (int)m_internalSubnets.size() || m_internalSubnets[row].builtIn) return;
            m_internalSubnets.removeAt(row);
            rebuildSnList();
            snRemoveBtn->setEnabled(false);
            snSetBitsBtn->setEnabled(false);
            if (m_graphWidget) m_graphWidget->setInternalSubnets(m_internalSubnets);
        });

        pv->addWidget(netGrp);
        pv->addStretch();
        stack->addWidget(page);
    }

    /* ── PAGE 2 — Performance ─────────────────────────────────────────── */
    {
        QWidget *page = new QWidget;
        QVBoxLayout *pv = new QVBoxLayout(page);
        pv->setSpacing(8); pv->setContentsMargins(0,4,0,4);

        QGroupBox *perfGrp = new QGroupBox("Performance");
        QVBoxLayout *perfBox = new QVBoxLayout(perfGrp);
        perfBox->setSpacing(6);

        QCheckBox *l2Chk = new QCheckBox("Enable Layer-2 / LLC analysis");
        l2Chk->setToolTip("Scans the full capture for MAC-layer protocol breakdown (EtherType, LLC DSAP/SSAP).\n"
                          "Disable if clicking MAC connections is slow on large captures.");
        l2Chk->setChecked(m_enableL2Analysis);

        QCheckBox *transportChk = new QCheckBox("Enable TCP / UDP transport statistics");
        transportChk->setToolTip("Scans the full capture for per-flow TCP/UDP metrics (window size, RTT, payload stats).\n"
                                 "Disable if Transport Details dialogs are slow on large captures.");
        transportChk->setChecked(m_enableTransportStats);

        QCheckBox *deepChk = new QCheckBox("Enable protocol deep inspection");
        deepChk->setToolTip("Scans the full capture for protocol-specific information (TLS, HTTP, SMB, DNS, …).\n"
                            "Disable to suppress per-protocol info dialogs on large captures.");
        deepChk->setChecked(m_enableDeepInspection);

        perfBox->addWidget(l2Chk);
        perfBox->addWidget(transportChk);
        perfBox->addWidget(deepChk);

        QObject::connect(l2Chk,        &QCheckBox::toggled, [this](bool on) { m_enableL2Analysis     = on; });
        QObject::connect(transportChk, &QCheckBox::toggled, [this](bool on) { m_enableTransportStats = on; });
        QObject::connect(deepChk,      &QCheckBox::toggled, [this](bool on) { m_enableDeepInspection = on; });

        pv->addWidget(perfGrp);
        pv->addStretch();
        stack->addWidget(page);
    }

    /* ── PAGE 3 — Graph Thresholds ────────────────────────────────────── */
    {
        QWidget *page = new QWidget;
        QVBoxLayout *pv = new QVBoxLayout(page);
        pv->setSpacing(8); pv->setContentsMargins(0,4,0,4);

        QGroupBox *threshGrp = new QGroupBox("Graph Thresholds");
        QVBoxLayout *threshBox = new QVBoxLayout(threshGrp);
        threshBox->setSpacing(6);

        QHBoxLayout *activeRow = new QHBoxLayout;
        QLabel *activeLabel = new QLabel("Active group:");
        QComboBox *activeCombo = new QComboBox;
        for (const auto &g : m_thresholdGroups)
            activeCombo->addItem(g.name);
        activeCombo->setCurrentIndex(m_activeThresholdGroup);
        activeRow->addWidget(activeLabel);
        activeRow->addWidget(activeCombo, 1);
        threshBox->addLayout(activeRow);

        QHBoxLayout *threshBtnRow = new QHBoxLayout;
        QPushButton *editGroupBtn = new QPushButton("Edit…");
        QPushButton *addGroupBtn  = new QPushButton("+ Add Group");
        QPushButton *delGroupBtn  = new QPushButton("Delete");
        delGroupBtn->setToolTip("Delete selected group (built-in profiles cannot be deleted)");
        delGroupBtn->setEnabled(activeCombo->currentIndex() >= 3);
        threshBtnRow->addWidget(editGroupBtn);
        threshBtnRow->addWidget(addGroupBtn);
        threshBtnRow->addWidget(delGroupBtn);
        threshBtnRow->addStretch();
        threshBox->addLayout(threshBtnRow);

        QObject::connect(activeCombo, QOverload<int>::of(&QComboBox::currentIndexChanged), [this, activeCombo, delGroupBtn](int idx) {
            delGroupBtn->setEnabled(idx >= 3);
            m_activeThresholdGroup = idx;
            if (m_graphWidget && idx >= 0 && idx < m_thresholdGroups.size())
                m_graphWidget->setThresholds(m_thresholdGroups[idx]);
        });
        QObject::connect(editGroupBtn, &QPushButton::clicked, [this, activeCombo]() {
            int idx = activeCombo->currentIndex();
            if (idx < 0 || idx >= m_thresholdGroups.size()) return;
            showThresholdGroupEditor(m_thresholdGroups[idx].name);
            for (int i = 0; i < m_thresholdGroups.size(); i++)
                activeCombo->setItemText(i, m_thresholdGroups[i].name);
        });
        QObject::connect(addGroupBtn, &QPushButton::clicked, [this, activeCombo, delGroupBtn]() {
            showThresholdGroupEditor(QString());
            activeCombo->blockSignals(true);
            activeCombo->clear();
            for (const auto &g : m_thresholdGroups) activeCombo->addItem(g.name);
            activeCombo->setCurrentIndex(m_activeThresholdGroup);
            activeCombo->blockSignals(false);
            delGroupBtn->setEnabled(m_activeThresholdGroup >= 3);
        });
        QObject::connect(delGroupBtn, &QPushButton::clicked, [this, &dlg, activeCombo, delGroupBtn]() {
            int idx = activeCombo->currentIndex();
            if (idx < 3 || idx >= m_thresholdGroups.size()) return;
            auto reply = QMessageBox::question(&dlg, "Delete Threshold Group",
                QString("Delete group \"%1\"?").arg(m_thresholdGroups[idx].name),
                QMessageBox::Yes | QMessageBox::Cancel, QMessageBox::Cancel);
            if (reply != QMessageBox::Yes) return;
            m_thresholdGroups.removeAt(idx);
            m_activeThresholdGroup = 0;
            activeCombo->blockSignals(true);
            activeCombo->clear();
            for (const auto &g : m_thresholdGroups) activeCombo->addItem(g.name);
            activeCombo->setCurrentIndex(0);
            activeCombo->blockSignals(false);
            delGroupBtn->setEnabled(false);
            if (m_graphWidget) m_graphWidget->setThresholds(m_thresholdGroups[0]);
        });

        pv->addWidget(threshGrp);
        pv->addStretch();
        stack->addWidget(page);
    }

    /* ── PAGE 4 — Wi-Fi Thresholds ────────────────────────────────────── */
    {
        QWidget *page = new QWidget;
        QVBoxLayout *pv = new QVBoxLayout(page);
        pv->setSpacing(8); pv->setContentsMargins(0,4,0,4);

        QGroupBox *wifiGrp = new QGroupBox("Wi-Fi Signal Quality Thresholds");
        QVBoxLayout *wifiBox = new QVBoxLayout(wifiGrp);
        wifiBox->setSpacing(6);

        QLabel *wifiNote = new QLabel(
            "Controls the RSSI (dBm) boundaries used to colour Wi-Fi connections and the legend.\n"
            "Default: Excellent ≥ −60, Good ≥ −65, Fair ≥ −70, Poor below −70.");
        wifiNote->setWordWrap(true);
        wifiNote->setStyleSheet(dark ? "color:#aaa; font-size:8pt;" : "color:#555; font-size:8pt;");
        wifiBox->addWidget(wifiNote);

        QHBoxLayout *wifiActiveRow = new QHBoxLayout;
        QLabel *wifiActiveLabel = new QLabel("Active group:");
        QComboBox *wifiActiveCombo = new QComboBox;
        for (const auto &g : m_wifiThresholdGroups)
            wifiActiveCombo->addItem(g.name);
        wifiActiveCombo->setCurrentIndex(m_activeWifiThresholdGroup);
        wifiActiveRow->addWidget(wifiActiveLabel);
        wifiActiveRow->addWidget(wifiActiveCombo, 1);
        wifiBox->addLayout(wifiActiveRow);

        QHBoxLayout *wifiBtnRow = new QHBoxLayout;
        QPushButton *wifiEditBtn = new QPushButton("Edit…");
        QPushButton *wifiAddBtn  = new QPushButton("+ Add Group");
        QPushButton *wifiDelBtn  = new QPushButton("Delete");
        wifiDelBtn->setToolTip("Delete the selected group (Default cannot be deleted)");
        wifiDelBtn->setEnabled(m_activeWifiThresholdGroup > 0);
        wifiBtnRow->addWidget(wifiEditBtn);
        wifiBtnRow->addWidget(wifiAddBtn);
        wifiBtnRow->addWidget(wifiDelBtn);
        wifiBtnRow->addStretch();
        wifiBox->addLayout(wifiBtnRow);

        QObject::connect(wifiActiveCombo, QOverload<int>::of(&QComboBox::currentIndexChanged), [this, wifiActiveCombo, wifiDelBtn](int idx) {
            wifiDelBtn->setEnabled(idx > 0);
            m_activeWifiThresholdGroup = idx;
            if (m_circleWidget && idx >= 0 && idx < m_wifiThresholdGroups.size())
                m_circleWidget->setWifiThresholds(m_wifiThresholdGroups[idx]);
            updateLegend();
        });
        QObject::connect(wifiEditBtn, &QPushButton::clicked, [this, wifiActiveCombo]() {
            int idx = wifiActiveCombo->currentIndex();
            if (idx < 0 || idx >= m_wifiThresholdGroups.size()) return;
            showWifiThresholdGroupEditor(m_wifiThresholdGroups[idx].name);
            for (int i = 0; i < m_wifiThresholdGroups.size(); i++)
                wifiActiveCombo->setItemText(i, m_wifiThresholdGroups[i].name);
            updateLegend();
        });
        QObject::connect(wifiAddBtn, &QPushButton::clicked, [this, wifiActiveCombo, wifiDelBtn]() {
            showWifiThresholdGroupEditor(QString());
            wifiActiveCombo->blockSignals(true);
            wifiActiveCombo->clear();
            for (const auto &g : m_wifiThresholdGroups) wifiActiveCombo->addItem(g.name);
            wifiActiveCombo->setCurrentIndex(m_activeWifiThresholdGroup);
            wifiActiveCombo->blockSignals(false);
            wifiDelBtn->setEnabled(m_activeWifiThresholdGroup > 0);
        });
        QObject::connect(wifiDelBtn, &QPushButton::clicked, [this, &dlg, wifiActiveCombo, wifiDelBtn]() {
            int idx = wifiActiveCombo->currentIndex();
            if (idx <= 0 || idx >= m_wifiThresholdGroups.size()) return;
            auto reply = QMessageBox::question(&dlg, "Delete Wi-Fi Threshold Group",
                QString("Delete group \"%1\"?").arg(m_wifiThresholdGroups[idx].name),
                QMessageBox::Yes | QMessageBox::Cancel, QMessageBox::Cancel);
            if (reply != QMessageBox::Yes) return;
            m_wifiThresholdGroups.removeAt(idx);
            m_activeWifiThresholdGroup = 0;
            wifiActiveCombo->blockSignals(true);
            wifiActiveCombo->clear();
            for (const auto &g : m_wifiThresholdGroups) wifiActiveCombo->addItem(g.name);
            wifiActiveCombo->setCurrentIndex(0);
            wifiActiveCombo->blockSignals(false);
            wifiDelBtn->setEnabled(false);
            if (m_circleWidget) m_circleWidget->setWifiThresholds(m_wifiThresholdGroups[0]);
            updateLegend();
        });

        pv->addWidget(wifiGrp);
        pv->addStretch();
        stack->addWidget(page);
    }

    /* ── PAGE 5 — Reports ─────────────────────────────────────────────── */
    {
        QWidget *page = new QWidget;
        QVBoxLayout *pv = new QVBoxLayout(page);
        pv->setSpacing(8); pv->setContentsMargins(0,4,0,4);

        QGroupBox *rptGrp = new QGroupBox("Configure Reports");
        QFormLayout *rptForm = new QFormLayout(rptGrp);
        rptForm->setLabelAlignment(Qt::AlignRight | Qt::AlignVCenter);
        rptForm->setHorizontalSpacing(12);
        rptForm->setVerticalSpacing(8);
        rptForm->setContentsMargins(8, 12, 8, 8);

        QLineEdit *rptCompany    = new QLineEdit(m_reportCompany);
        QLineEdit *rptPreparedBy = new QLineEdit(m_reportPreparedBy);
        QLineEdit *rptProject    = new QLineEdit(m_reportProject);
        QLineEdit *rptComments   = new QLineEdit(m_reportComments);
        rptCompany   ->setPlaceholderText("e.g. Acme Corp");
        rptPreparedBy->setPlaceholderText("e.g. Jane Smith");
        rptProject   ->setPlaceholderText("e.g. Q2 Security Audit (optional)");
        rptComments  ->setPlaceholderText("e.g. Demo Segment Analysis");

        QComboBox *rptPaper = new QComboBox;
        rptPaper->addItem("A4  (210 × 297 mm)");
        rptPaper->addItem("Legal  (8.5 × 14 in)");
        rptPaper->setCurrentIndex(m_reportPaperSize);

        rptForm->addRow("Company Name:", rptCompany);
        rptForm->addRow("Prepared by:",  rptPreparedBy);
        rptForm->addRow("Project:",      rptProject);
        rptForm->addRow("Comments:",     rptComments);
        rptForm->addRow("Paper Size:",   rptPaper);

        /* Capture edits into members when Close is pressed — connect below */
        QObject::connect(rptCompany,    &QLineEdit::textEdited, [this](const QString &t){ m_reportCompany    = t.trimmed(); });
        QObject::connect(rptPreparedBy, &QLineEdit::textEdited, [this](const QString &t){ m_reportPreparedBy = t.trimmed(); });
        QObject::connect(rptProject,    &QLineEdit::textEdited, [this](const QString &t){ m_reportProject    = t.trimmed(); });
        QObject::connect(rptComments,   &QLineEdit::textEdited, [this](const QString &t){ m_reportComments   = t.trimmed(); });
        QObject::connect(rptPaper, QOverload<int>::of(&QComboBox::currentIndexChanged), [this](int idx){ m_reportPaperSize = idx; });

        pv->addWidget(rptGrp);
        pv->addStretch();
        stack->addWidget(page);
    }

    /* ── PAGE 6 — About ───────────────────────────────────────────────── */
    {
        QWidget *page = new QWidget;
        QVBoxLayout *pv = new QVBoxLayout(page);
        pv->setSpacing(8); pv->setContentsMargins(0,4,0,4);

        QGroupBox *aboutGrp = new QGroupBox("About");
        QVBoxLayout *aboutBox = new QVBoxLayout(aboutGrp);
        aboutBox->setSpacing(5);

        const QString platform =
#if defined(Q_OS_MACOS)
            "macOS Universal";
#elif defined(Q_OS_LINUX)
            "Linux x86_64";
#elif defined(Q_OS_WIN)
            "Windows x86_64";
#else
            "Unknown platform";
#endif
        QLabel *verLabel = new QLabel(
            QString("<b>PacketCircle %1</b> &nbsp;&middot;&nbsp; %2 &nbsp;&middot;&nbsp; Qt %3")
            .arg(QLatin1String(PC_VERSION), platform, QLatin1String(QT_VERSION_STR)));
        verLabel->setTextFormat(Qt::RichText);
        aboutBox->addWidget(verLabel);

        QStringList pluginSearchPaths = {
            QDir::homePath() + "/.local/lib/wireshark/plugins/4-6/epan/packetcircle.so",
            QDir::homePath() + "/.local/lib/wireshark/plugins/4.6/epan/packetcircle.so",
#if defined(Q_OS_WIN)
            QDir::fromNativeSeparators(qEnvironmentVariable("APPDATA"))
                + "/Wireshark/plugins/4.6/epan/packetcircle.dll",
            QDir::fromNativeSeparators(qEnvironmentVariable("APPDATA"))
                + "/Wireshark/plugins/4-6/epan/packetcircle.dll",
            QDir::fromNativeSeparators(qEnvironmentVariable("LOCALAPPDATA"))
                + "/Wireshark/plugins/4.6/epan/packetcircle.dll",
            QDir::fromNativeSeparators(qEnvironmentVariable("LOCALAPPDATA"))
                + "/Wireshark/plugins/4-6/epan/packetcircle.dll",
            "C:/Program Files/Wireshark/plugins/4.6/epan/packetcircle.dll",
            "C:/Program Files/Wireshark/plugins/4-6/epan/packetcircle.dll",
#endif
        };
        QString foundPluginPath;
        for (const QString &pp : pluginSearchPaths)
            if (QFile::exists(pp)) { foundPluginPath = pp; break; }

        QLabel *pathLabel = new QLabel(
            foundPluginPath.isEmpty()
            ? QString("<span style='color:%1;'>&#9888; Plugin file not found at expected location</span>")
                .arg(dark ? "#f0c040" : "#b07800")
            : QString("<span style='color:%1;'>&#10003; %2</span>")
                .arg(dark ? "#6ec96e" : "#27ae60", foundPluginPath.toHtmlEscaped()));
        pathLabel->setTextFormat(Qt::RichText);
        pathLabel->setWordWrap(true);
        aboutBox->addWidget(pathLabel);

        QHBoxLayout *updateRow = new QHBoxLayout;
        QPushButton *checkUpdateBtn  = new QPushButton("Check for Updates");
        QLabel      *updateStatusLbl = new QLabel("");
        updateStatusLbl->setTextFormat(Qt::RichText);
        updateStatusLbl->setOpenExternalLinks(true);
        updateRow->addWidget(checkUpdateBtn);
        updateRow->addWidget(updateStatusLbl, 1);
        aboutBox->addLayout(updateRow);

        QObject::connect(checkUpdateBtn, &QPushButton::clicked,
                         [this, checkUpdateBtn, updateStatusLbl]() {
            QPointer<QPushButton> safeBtn(checkUpdateBtn);
            QPointer<QLabel>      safeLbl(updateStatusLbl);
            if (safeBtn) safeBtn->setEnabled(false);
            if (safeLbl) safeLbl->setText("Checking…");
            if (!m_networkManager) m_networkManager = new QNetworkAccessManager(this);
            QNetworkRequest req(QUrl("https://api.github.com/repos/netwho/PacketCircle/releases/latest"));
            req.setHeader(QNetworkRequest::UserAgentHeader,
                          QString("PacketCircle/%1").arg(QLatin1String(PC_VERSION + 2)));
            req.setRawHeader("Accept", "application/vnd.github.v3+json");
            QNetworkReply *reply = m_networkManager->get(req);
            QObject::connect(reply, &QNetworkReply::finished,
                             [reply, safeBtn, safeLbl]() mutable {
                reply->deleteLater();
                if (safeBtn) safeBtn->setEnabled(true);
                if (!safeLbl) return;
                if (reply->error() != QNetworkReply::NoError) {
                    safeLbl->setText(
                        QString("<span style='color:#e07070;'>Could not reach GitHub (%1)</span>")
                        .arg(reply->errorString().toHtmlEscaped()));
                    return;
                }
                QString tag = QJsonDocument::fromJson(reply->readAll())
                                  .object().value("tag_name").toString();
                if (tag.isEmpty()) {
                    safeLbl->setText("<span style='color:#e07070;'>No release info found</span>");
                    return;
                }
                auto strip = [](const QString &s) {
                    QString r = s.toLower();
                    if (r.startsWith("v.")) return r.mid(2);
                    if (r.startsWith("v"))  return r.mid(1);
                    return r;
                };
                auto isNewer = [&](const QString &remote, const QString &current) {
                    auto parts = [](const QString &v) {
                        QList<int> out;
                        for (const QString &p : v.split('.')) out.append(p.toInt());
                        while (out.size() < 3) out.append(0);
                        return out;
                    };
                    QList<int> r = parts(remote), c = parts(current);
                    for (int i = 0; i < 3; i++) {
                        if (r[i] > c[i]) return true;
                        if (r[i] < c[i]) return false;
                    }
                    return false;
                };
                if (!isNewer(strip(tag), strip(QString(PC_VERSION)))) {
                    safeLbl->setText("<span style='color:#6ec96e;'>&#10003; Up to date</span>");
                } else {
                    static const QString dlUrl =
                        "https://raw.githubusercontent.com/netwho/PacketCircle/main/installer.zip";
                    auto reply2 = QMessageBox::question(
                        nullptr, "Update Available",
                        QString("PacketCircle %1 is available (you have %2).\n\nDownload installer.zip now?")
                        .arg(tag, QLatin1String(PC_VERSION)),
                        QMessageBox::Yes | QMessageBox::No, QMessageBox::Yes);
                    if (reply2 == QMessageBox::Yes)
                        QDesktopServices::openUrl(QUrl(dlUrl));
                    safeLbl->setText(
                        QString("<span style='color:#f0c040;'>%1 available</span>")
                        .arg(tag.toHtmlEscaped()));
                }
            });
        });

        pv->addWidget(aboutGrp);
        pv->addStretch();
        stack->addWidget(page);
    }

    /* ── Footer: Reset All + Close ────────────────────────────────────── */
    QFrame *sep = new QFrame;
    sep->setFrameShape(QFrame::HLine);
    sep->setFrameShadow(QFrame::Sunken);
    outerLayout->addWidget(sep);

    QHBoxLayout *footer = new QHBoxLayout;
    QPushButton *resetBtn = new QPushButton("Reset All Settings…");
    resetBtn->setToolTip("Reset all settings to their defaults");
    if (dark) resetBtn->setStyleSheet("color:#f09090;");
    QPushButton *closeBtn = new QPushButton("Close");
    footer->addWidget(resetBtn);
    footer->addStretch();
    footer->addWidget(closeBtn);
    outerLayout->addLayout(footer);

    /* ── Switch pages + resize ────────────────────────────────────────── */
    stack->setCurrentIndex(initialPage);
    sectionCombo->setCurrentIndex(initialPage);
    QObject::connect(sectionCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
                     [stack, &dlg](int idx) {
        stack->setCurrentIndex(idx);
        QTimer::singleShot(0, &dlg, [&dlg]() { dlg.adjustSize(); });
    });

    /* ── Reset All ────────────────────────────────────────────────────── */
    QObject::connect(resetBtn, &QPushButton::clicked, [this, &dlg]() {
        auto reply = QMessageBox::question(&dlg, "Reset Settings",
            "Reset all window, display, and integration settings to their defaults?\n\n"
            "ntopng connection settings (host, port, credentials) are preserved.",
            QMessageBox::Yes | QMessageBox::Cancel, QMessageBox::Cancel);
        if (reply != QMessageBox::Yes) return;

        QFile::remove(preferencesFilePath());
        m_topN = 10; m_useBytes = FALSE; m_useMAC = FALSE;
        m_ntopEnabled = true; m_malcolmEnabled = false;
        if (m_top10Btn)  m_top10Btn->setChecked(true);
        if (m_top25Btn)  m_top25Btn->setChecked(false);
        if (m_top50Btn)  m_top50Btn->setChecked(false);
        if (m_packetsBtn) m_packetsBtn->setChecked(true);
        if (m_bytesBtn)   m_bytesBtn->setChecked(false);
        if (m_ipBtn)   m_ipBtn->setChecked(true);
        if (m_macBtn)  m_macBtn->setChecked(false);
        if (m_circleBtn) m_circleBtn->setChecked(true);
        if (m_tableBtn)  m_tableBtn->setChecked(false);
        if (m_viewStack) m_viewStack->setCurrentIndex(0);
        if (m_lineThicknessCheckBox) m_lineThicknessCheckBox->setChecked(false);
        updateSearchBarForMode();
        if (m_sendToNtopBtn)    m_sendToNtopBtn->setVisible(true);
        if (m_sendToMalcolmBtn) m_sendToMalcolmBtn->setVisible(false);
        m_enableL2Analysis = true; m_enableTransportStats = true; m_enableDeepInspection = true;
        resize(1280, 780);
        m_thresholdGroups.clear();
        m_thresholdGroups.append(GraphWidget::GraphThresholds::defaults());
        m_thresholdGroups.append(GraphWidget::GraphThresholds::strict());
        m_thresholdGroups.append(GraphWidget::GraphThresholds::tolerant());
        m_activeThresholdGroup = 0;
        if (m_graphWidget) m_graphWidget->setThresholds(m_thresholdGroups[0]);
        m_wifiThresholdGroups.clear();
        m_wifiThresholdGroups.append(CircleWidget::WifiThresholds::defaults());
        m_activeWifiThresholdGroup = 0;
        if (m_circleWidget) m_circleWidget->setWifiThresholds(m_wifiThresholdGroups[0]);
        updateLegend();
        savePreferences();
        QMessageBox::information(&dlg, "Reset Complete", "Settings have been reset to defaults.");
        dlg.accept();
    });

    QObject::connect(closeBtn, &QPushButton::clicked, &dlg, &QDialog::accept);

    dlg.exec();
    savePreferences();
}

/* ── Integration sub-dialog ─────────────────────────────────────────────── */
void MainWindow::showIntegrationDialog()
{
    bool dark = isDarkTheme();
    QDialog dlg(this);
    dlg.setWindowTitle("Integration");
    dlg.setMinimumWidth(420);

    if (dark) {
        dlg.setStyleSheet(
            "QDialog { background:#1e1e1e; color:#e0e0e0; }"
            "QLabel { color:#e0e0e0; }"
            "QGroupBox { color:#e0e0e0; border:1px solid #444; border-radius:4px; margin-top:8px; }"
            "QGroupBox::title { subcontrol-origin:margin; left:10px; padding:0 4px; color:#90caf9; }"
            "QCheckBox { color:#e0e0e0; }"
            "QPushButton { background:#333; color:#e0e0e0; border:1px solid #555; padding:4px 14px; border-radius:3px; }"
            "QPushButton:hover:enabled { background:#444; }");
    }

    QVBoxLayout *main = new QVBoxLayout(&dlg);
    main->setSpacing(8);
    main->setContentsMargins(14, 10, 14, 10);

    QGroupBox *intGrp = new QGroupBox("Integrations");
    QVBoxLayout *intBox = new QVBoxLayout(intGrp);
    intBox->setSpacing(6);

    QCheckBox *ntopChk = new QCheckBox("ntopng");
    ntopChk->setChecked(m_ntopEnabled);
    QPushButton *cfgNtopBtn = new QPushButton("Configure…");
    cfgNtopBtn->setEnabled(m_ntopEnabled);
    QPushButton *cfgCertBtn = new QPushButton("CA Cert…");
    cfgCertBtn->setToolTip("Set a custom CA certificate for TLS connections to ntopng");

    QHBoxLayout *ntopRow = new QHBoxLayout;
    ntopRow->addWidget(ntopChk, 1);
    ntopRow->addWidget(cfgNtopBtn);
    ntopRow->addWidget(cfgCertBtn);
    intBox->addLayout(ntopRow);

    QCheckBox *malcolmChk = new QCheckBox("Malcolm / Arkime");
    malcolmChk->setChecked(m_malcolmEnabled);
    QPushButton *cfgMalcolmBtn = new QPushButton("Configure…");
    cfgMalcolmBtn->setEnabled(m_malcolmEnabled);

    QHBoxLayout *malcolmRow = new QHBoxLayout;
    malcolmRow->addWidget(malcolmChk, 1);
    malcolmRow->addWidget(cfgMalcolmBtn);
    intBox->addLayout(malcolmRow);

    main->addWidget(intGrp);

    QHBoxLayout *btnRow = new QHBoxLayout;
    btnRow->addStretch();
    QPushButton *closeBtn = new QPushButton("Close");
    btnRow->addWidget(closeBtn);
    main->addLayout(btnRow);

    QObject::connect(ntopChk, &QCheckBox::toggled, [&](bool on) {
        cfgNtopBtn->setEnabled(on);
        m_ntopEnabled = on;
        if (m_sendToNtopBtn) m_sendToNtopBtn->setVisible(on);
    });
    QObject::connect(cfgNtopBtn,    &QPushButton::clicked, [&]() { showNtopngConfigDialog(); });
    QObject::connect(cfgCertBtn,    &QPushButton::clicked, [&]() { showCaCertConfigDialog(); });
    QObject::connect(malcolmChk, &QCheckBox::toggled, [&](bool on) {
        cfgMalcolmBtn->setEnabled(on);
        m_malcolmEnabled = on;
        if (m_sendToMalcolmBtn) m_sendToMalcolmBtn->setVisible(on);
    });
    QObject::connect(cfgMalcolmBtn, &QPushButton::clicked, [&]() { showMalcolmConfigDialog(); });
    QObject::connect(closeBtn, &QPushButton::clicked, &dlg, &QDialog::accept);

    dlg.exec();
    savePreferences();
}

/* ── Internal Networks sub-dialog ───────────────────────────────────────── */
void MainWindow::showInternalNetworksDialog()
{
    bool dark = isDarkTheme();
    QDialog dlg(this);
    dlg.setWindowTitle("Internal Networks");
    dlg.setMinimumWidth(440);

    if (dark) {
        dlg.setStyleSheet(
            "QDialog { background:#1e1e1e; color:#e0e0e0; }"
            "QLabel { color:#e0e0e0; }"
            "QGroupBox { color:#e0e0e0; border:1px solid #444; border-radius:4px; margin-top:8px; }"
            "QGroupBox::title { subcontrol-origin:margin; left:10px; padding:0 4px; color:#90caf9; }"
            "QListWidget { background:#2a2a2a; color:#e0e0e0; border:1px solid #444; }"
            "QLineEdit { background:#2a2a2a; color:#e0e0e0; border:1px solid #555; padding:2px; }"
            "QSpinBox { background:#2a2a2a; color:#e0e0e0; border:1px solid #555; }"
            "QPushButton { background:#333; color:#e0e0e0; border:1px solid #555; padding:4px 14px; border-radius:3px; }"
            "QPushButton:hover:enabled { background:#444; }");
    }

    QVBoxLayout *main = new QVBoxLayout(&dlg);
    main->setSpacing(8);
    main->setContentsMargins(14, 10, 14, 10);

    QGroupBox *netGrp = new QGroupBox("Internal Networks (Graph)");
    QVBoxLayout *netBox = new QVBoxLayout(netGrp);
    netBox->setSpacing(6);

    QLabel *netNote = new QLabel("Subnets treated as Internal in cluster view. Change /bits to adjust granularity.");
    netNote->setWordWrap(true);
    netBox->addWidget(netNote);

    QListWidget *snList = new QListWidget;
    snList->setFixedHeight(100);
    snList->setSelectionMode(QAbstractItemView::SingleSelection);
    auto rebuildSnList = [&]() {
        snList->clear();
        for (const auto &sn : m_internalSubnets)
            snList->addItem(QString("%1/%2%3").arg(sn.prefix).arg(sn.bits)
                            .arg(sn.builtIn ? " (built-in)" : ""));
    };
    rebuildSnList();
    netBox->addWidget(snList);

    QHBoxLayout *snAddRow = new QHBoxLayout;
    QLineEdit *snIpEdit = new QLineEdit;
    snIpEdit->setPlaceholderText("IP prefix (e.g. 10.5.0.0)");
    QLabel *snSlash = new QLabel("/");
    QSpinBox *snBits = new QSpinBox;
    snBits->setRange(1, 32);
    snBits->setValue(24);
    QPushButton *snAddBtn = new QPushButton("Add");
    snAddRow->addWidget(snIpEdit, 1);
    snAddRow->addWidget(snSlash);
    snAddRow->addWidget(snBits);
    snAddRow->addWidget(snAddBtn);
    netBox->addLayout(snAddRow);

    QPushButton *snRemoveBtn  = new QPushButton("Remove Selected");
    QPushButton *snSetBitsBtn = new QPushButton("Set /bits for selected");
    snRemoveBtn->setEnabled(false);
    snSetBitsBtn->setEnabled(false);
    snSetBitsBtn->setToolTip("Update the clustering prefix length for the selected subnet");
    QHBoxLayout *snBtnRow = new QHBoxLayout;
    snBtnRow->addWidget(snRemoveBtn);
    snBtnRow->addWidget(snSetBitsBtn);
    netBox->addLayout(snBtnRow);

    QObject::connect(snList, &QListWidget::currentRowChanged, [&](int row) {
        bool valid = (row >= 0 && row < (int)m_internalSubnets.size());
        snRemoveBtn->setEnabled(valid && !m_internalSubnets[row].builtIn);
        snSetBitsBtn->setEnabled(valid);
        if (valid) snBits->setValue(m_internalSubnets[row].bits);
    });
    QObject::connect(snSetBitsBtn, &QPushButton::clicked, [&]() {
        int row = snList->currentRow();
        if (row < 0 || row >= (int)m_internalSubnets.size()) return;
        m_internalSubnets[row].bits = snBits->value();
        rebuildSnList();
        snList->setCurrentRow(row);
        if (m_graphWidget) m_graphWidget->setInternalSubnets(m_internalSubnets);
    });
    QObject::connect(snAddBtn, &QPushButton::clicked, [&]() {
        QString prefix = snIpEdit->text().trimmed();
        if (prefix.isEmpty()) return;
        GraphWidget::InternalSubnet sn;
        sn.prefix  = prefix;
        sn.bits    = snBits->value();
        sn.builtIn = false;
        m_internalSubnets.append(sn);
        rebuildSnList();
        snIpEdit->clear();
        if (m_graphWidget) m_graphWidget->setInternalSubnets(m_internalSubnets);
    });
    QObject::connect(snRemoveBtn, &QPushButton::clicked, [&]() {
        int row = snList->currentRow();
        if (row < 0 || row >= (int)m_internalSubnets.size()) return;
        if (m_internalSubnets[row].builtIn) return;
        m_internalSubnets.removeAt(row);
        rebuildSnList();
        snRemoveBtn->setEnabled(false);
        snSetBitsBtn->setEnabled(false);
        if (m_graphWidget) m_graphWidget->setInternalSubnets(m_internalSubnets);
    });

    main->addWidget(netGrp);

    QHBoxLayout *btnRow = new QHBoxLayout;
    btnRow->addStretch();
    QPushButton *closeBtn = new QPushButton("Close");
    btnRow->addWidget(closeBtn);
    main->addLayout(btnRow);
    QObject::connect(closeBtn, &QPushButton::clicked, &dlg, &QDialog::accept);

    dlg.exec();
    savePreferences();
}

/* ── Performance sub-dialog ─────────────────────────────────────────────── */
void MainWindow::showPerformanceDialog()
{
    bool dark = isDarkTheme();
    QDialog dlg(this);
    dlg.setWindowTitle("Performance");
    dlg.setMinimumWidth(420);

    if (dark) {
        dlg.setStyleSheet(
            "QDialog { background:#1e1e1e; color:#e0e0e0; }"
            "QLabel { color:#e0e0e0; }"
            "QGroupBox { color:#e0e0e0; border:1px solid #444; border-radius:4px; margin-top:8px; }"
            "QGroupBox::title { subcontrol-origin:margin; left:10px; padding:0 4px; color:#90caf9; }"
            "QCheckBox { color:#e0e0e0; }"
            "QPushButton { background:#333; color:#e0e0e0; border:1px solid #555; padding:4px 14px; border-radius:3px; }"
            "QPushButton:hover:enabled { background:#444; }");
    }

    QVBoxLayout *main = new QVBoxLayout(&dlg);
    main->setSpacing(8);
    main->setContentsMargins(14, 10, 14, 10);

    QGroupBox *perfGrp = new QGroupBox("Performance");
    QVBoxLayout *perfBox = new QVBoxLayout(perfGrp);
    perfBox->setSpacing(6);

    QCheckBox *l2Chk = new QCheckBox("Enable Layer-2 / LLC analysis");
    l2Chk->setToolTip("Scans the full capture for MAC-layer protocol breakdown (EtherType, LLC DSAP/SSAP).\n"
                      "Disable if clicking MAC connections is slow on large captures.");
    l2Chk->setChecked(m_enableL2Analysis);

    QCheckBox *transportChk = new QCheckBox("Enable TCP / UDP transport statistics");
    transportChk->setToolTip("Scans the full capture for per-flow TCP/UDP metrics (window size, RTT, payload stats).\n"
                             "Disable if Transport Details dialogs are slow on large captures.");
    transportChk->setChecked(m_enableTransportStats);

    QCheckBox *deepChk = new QCheckBox("Enable protocol deep inspection");
    deepChk->setToolTip("Scans the full capture for protocol-specific information (TLS, HTTP, SMB, DNS, …).\n"
                        "Disable to suppress per-protocol info dialogs on large captures.");
    deepChk->setChecked(m_enableDeepInspection);

    perfBox->addWidget(l2Chk);
    perfBox->addWidget(transportChk);
    perfBox->addWidget(deepChk);
    main->addWidget(perfGrp);

    QHBoxLayout *btnRow = new QHBoxLayout;
    btnRow->addStretch();
    QPushButton *closeBtn = new QPushButton("Close");
    btnRow->addWidget(closeBtn);
    main->addLayout(btnRow);

    QObject::connect(l2Chk,        &QCheckBox::toggled, [&](bool on) { m_enableL2Analysis     = on; });
    QObject::connect(transportChk, &QCheckBox::toggled, [&](bool on) { m_enableTransportStats = on; });
    QObject::connect(deepChk,      &QCheckBox::toggled, [&](bool on) { m_enableDeepInspection = on; });
    QObject::connect(closeBtn, &QPushButton::clicked, &dlg, &QDialog::accept);

    dlg.exec();
    savePreferences();
}

/* ── Graph Thresholds sub-dialog ────────────────────────────────────────── */
void MainWindow::showGraphThresholdsDialog()
{
    bool dark = isDarkTheme();
    QDialog dlg(this);
    dlg.setWindowTitle("Graph Thresholds");
    dlg.setMinimumWidth(400);

    if (dark) {
        dlg.setStyleSheet(
            "QDialog { background:#1e1e1e; color:#e0e0e0; }"
            "QLabel { color:#e0e0e0; }"
            "QGroupBox { color:#e0e0e0; border:1px solid #444; border-radius:4px; margin-top:8px; }"
            "QGroupBox::title { subcontrol-origin:margin; left:10px; padding:0 4px; color:#90caf9; }"
            "QComboBox { background:#333; color:#e0e0e0; border:1px solid #555; }"
            "QPushButton { background:#333; color:#e0e0e0; border:1px solid #555; padding:4px 14px; border-radius:3px; }"
            "QPushButton:hover:enabled { background:#444; }"
            "QPushButton:disabled { color:#555; border-color:#444; background:#2a2a2a; }");
    }

    QVBoxLayout *main = new QVBoxLayout(&dlg);
    main->setSpacing(8);
    main->setContentsMargins(14, 10, 14, 10);

    QGroupBox *threshGrp = new QGroupBox("Graph Thresholds");
    QVBoxLayout *threshBox = new QVBoxLayout(threshGrp);
    threshBox->setSpacing(6);

    QHBoxLayout *activeRow = new QHBoxLayout;
    QLabel *activeLabel = new QLabel("Active group:");
    QComboBox *activeCombo = new QComboBox;
    for (const auto &g : m_thresholdGroups)
        activeCombo->addItem(g.name);
    activeCombo->setCurrentIndex(m_activeThresholdGroup);
    activeRow->addWidget(activeLabel);
    activeRow->addWidget(activeCombo, 1);
    threshBox->addLayout(activeRow);

    QHBoxLayout *threshBtnRow = new QHBoxLayout;
    QPushButton *editGroupBtn = new QPushButton("Edit…");
    QPushButton *addGroupBtn  = new QPushButton("+ Add Group");
    QPushButton *delGroupBtn  = new QPushButton("Delete");
    delGroupBtn->setToolTip("Delete selected group (built-in profiles cannot be deleted)");
    delGroupBtn->setEnabled(activeCombo->currentIndex() >= 3);
    threshBtnRow->addWidget(editGroupBtn);
    threshBtnRow->addWidget(addGroupBtn);
    threshBtnRow->addWidget(delGroupBtn);
    threshBtnRow->addStretch();
    threshBox->addLayout(threshBtnRow);
    main->addWidget(threshGrp);

    QHBoxLayout *btnRow = new QHBoxLayout;
    btnRow->addStretch();
    QPushButton *closeBtn = new QPushButton("Close");
    btnRow->addWidget(closeBtn);
    main->addLayout(btnRow);

    QObject::connect(activeCombo, QOverload<int>::of(&QComboBox::currentIndexChanged), [&](int idx) {
        delGroupBtn->setEnabled(idx >= 3);
        m_activeThresholdGroup = idx;
        if (m_graphWidget && idx >= 0 && idx < m_thresholdGroups.size())
            m_graphWidget->setThresholds(m_thresholdGroups[idx]);
    });
    QObject::connect(editGroupBtn, &QPushButton::clicked, [&]() {
        int idx = activeCombo->currentIndex();
        if (idx < 0 || idx >= m_thresholdGroups.size()) return;
        showThresholdGroupEditor(m_thresholdGroups[idx].name);
        for (int i = 0; i < m_thresholdGroups.size(); i++)
            activeCombo->setItemText(i, m_thresholdGroups[i].name);
    });
    QObject::connect(addGroupBtn, &QPushButton::clicked, [&]() {
        showThresholdGroupEditor(QString());
        activeCombo->blockSignals(true);
        activeCombo->clear();
        for (const auto &g : m_thresholdGroups)
            activeCombo->addItem(g.name);
        activeCombo->setCurrentIndex(m_activeThresholdGroup);
        activeCombo->blockSignals(false);
        delGroupBtn->setEnabled(m_activeThresholdGroup > 0);
    });
    QObject::connect(delGroupBtn, &QPushButton::clicked, [&]() {
        int idx = activeCombo->currentIndex();
        if (idx < 3 || idx >= m_thresholdGroups.size()) return;
        auto reply = QMessageBox::question(&dlg, "Delete Threshold Group",
            QString("Delete group \"%1\"?").arg(m_thresholdGroups[idx].name),
            QMessageBox::Yes | QMessageBox::Cancel, QMessageBox::Cancel);
        if (reply != QMessageBox::Yes) return;
        m_thresholdGroups.removeAt(idx);
        m_activeThresholdGroup = 0;
        activeCombo->blockSignals(true);
        activeCombo->clear();
        for (const auto &g : m_thresholdGroups)
            activeCombo->addItem(g.name);
        activeCombo->setCurrentIndex(0);
        activeCombo->blockSignals(false);
        delGroupBtn->setEnabled(activeCombo->currentIndex() >= 3);
        if (m_graphWidget) m_graphWidget->setThresholds(m_thresholdGroups[0]);
    });
    QObject::connect(closeBtn, &QPushButton::clicked, &dlg, &QDialog::accept);

    dlg.exec();
    savePreferences();
}

/* ── WiFi Thresholds sub-dialog ─────────────────────────────────────────── */
void MainWindow::showWifiThresholdsDialog()
{
    bool dark = isDarkTheme();
    QDialog dlg(this);
    dlg.setWindowTitle("WiFi Thresholds");
    dlg.setMinimumWidth(400);

    if (dark) {
        dlg.setStyleSheet(
            "QDialog { background:#1e1e1e; color:#e0e0e0; }"
            "QLabel { color:#e0e0e0; }"
            "QGroupBox { color:#e0e0e0; border:1px solid #444; border-radius:4px; margin-top:8px; }"
            "QGroupBox::title { subcontrol-origin:margin; left:10px; padding:0 4px; color:#90caf9; }"
            "QComboBox { background:#333; color:#e0e0e0; border:1px solid #555; }"
            "QPushButton { background:#333; color:#e0e0e0; border:1px solid #555; padding:4px 14px; border-radius:3px; }"
            "QPushButton:hover:enabled { background:#444; }"
            "QPushButton:disabled { color:#555; border-color:#444; background:#2a2a2a; }");
    }

    QVBoxLayout *main = new QVBoxLayout(&dlg);
    main->setSpacing(8);
    main->setContentsMargins(14, 10, 14, 10);

    QGroupBox *threshGrp = new QGroupBox("WiFi Signal Quality Thresholds");
    QVBoxLayout *threshBox = new QVBoxLayout(threshGrp);
    threshBox->setSpacing(6);

    QLabel *note = new QLabel(
        "Controls the RSSI (dBm) boundaries used to colour Wi-Fi connections and the legend.\n"
        "Default: Excellent ≥ −60, Good ≥ −65, Fair ≥ −70, Poor below −70.");
    note->setWordWrap(true);
    note->setStyleSheet(dark ? "color:#aaa; font-size:8pt;" : "color:#555; font-size:8pt;");
    threshBox->addWidget(note);

    QHBoxLayout *activeRow = new QHBoxLayout;
    QLabel *activeLabel = new QLabel("Active group:");
    QComboBox *activeCombo = new QComboBox;
    for (const auto &g : m_wifiThresholdGroups)
        activeCombo->addItem(g.name);
    activeCombo->setCurrentIndex(m_activeWifiThresholdGroup);
    activeRow->addWidget(activeLabel);
    activeRow->addWidget(activeCombo, 1);
    threshBox->addLayout(activeRow);

    QHBoxLayout *btnRow2 = new QHBoxLayout;
    QPushButton *editGroupBtn = new QPushButton("Edit…");
    QPushButton *addGroupBtn  = new QPushButton("+ Add Group");
    QPushButton *delGroupBtn  = new QPushButton("Delete");
    delGroupBtn->setToolTip("Delete the selected group (Default cannot be deleted)");
    delGroupBtn->setEnabled(m_activeWifiThresholdGroup > 0);
    btnRow2->addWidget(editGroupBtn);
    btnRow2->addWidget(addGroupBtn);
    btnRow2->addWidget(delGroupBtn);
    btnRow2->addStretch();
    threshBox->addLayout(btnRow2);
    main->addWidget(threshGrp);

    QHBoxLayout *closeRow = new QHBoxLayout;
    closeRow->addStretch();
    QPushButton *closeBtn = new QPushButton("Close");
    closeRow->addWidget(closeBtn);
    main->addLayout(closeRow);

    QObject::connect(activeCombo, QOverload<int>::of(&QComboBox::currentIndexChanged), [&](int idx) {
        delGroupBtn->setEnabled(idx > 0);
        m_activeWifiThresholdGroup = idx;
        if (m_circleWidget && idx >= 0 && idx < m_wifiThresholdGroups.size())
            m_circleWidget->setWifiThresholds(m_wifiThresholdGroups[idx]);
        updateLegend();
    });
    QObject::connect(editGroupBtn, &QPushButton::clicked, [&]() {
        int idx = activeCombo->currentIndex();
        if (idx < 0 || idx >= m_wifiThresholdGroups.size()) return;
        showWifiThresholdGroupEditor(m_wifiThresholdGroups[idx].name);
        for (int i = 0; i < m_wifiThresholdGroups.size(); i++)
            activeCombo->setItemText(i, m_wifiThresholdGroups[i].name);
        updateLegend();
    });
    QObject::connect(addGroupBtn, &QPushButton::clicked, [&]() {
        showWifiThresholdGroupEditor(QString());
        activeCombo->blockSignals(true);
        activeCombo->clear();
        for (const auto &g : m_wifiThresholdGroups)
            activeCombo->addItem(g.name);
        activeCombo->setCurrentIndex(m_activeWifiThresholdGroup);
        activeCombo->blockSignals(false);
        delGroupBtn->setEnabled(m_activeWifiThresholdGroup > 0);
    });
    QObject::connect(delGroupBtn, &QPushButton::clicked, [&]() {
        int idx = activeCombo->currentIndex();
        if (idx <= 0 || idx >= m_wifiThresholdGroups.size()) return;
        auto reply = QMessageBox::question(&dlg, "Delete WiFi Threshold Group",
            QString("Delete group \"%1\"?").arg(m_wifiThresholdGroups[idx].name),
            QMessageBox::Yes | QMessageBox::Cancel, QMessageBox::Cancel);
        if (reply != QMessageBox::Yes) return;
        m_wifiThresholdGroups.removeAt(idx);
        m_activeWifiThresholdGroup = 0;
        activeCombo->blockSignals(true);
        activeCombo->clear();
        for (const auto &g : m_wifiThresholdGroups)
            activeCombo->addItem(g.name);
        activeCombo->setCurrentIndex(0);
        activeCombo->blockSignals(false);
        delGroupBtn->setEnabled(false);
        if (m_circleWidget)
            m_circleWidget->setWifiThresholds(m_wifiThresholdGroups[0]);
        updateLegend();
    });
    QObject::connect(closeBtn, &QPushButton::clicked, &dlg, &QDialog::accept);

    dlg.exec();
    savePreferences();
}

/* ── Reset All Settings sub-dialog ─────────────────────────────────────── */
void MainWindow::showResetSettingsDialog()
{
    auto reply = QMessageBox::question(this,
        "Reset Settings",
        "Reset all window, display, and integration settings to their defaults?\n\n"
        "ntopng connection settings (host, port, credentials) are preserved.",
        QMessageBox::Yes | QMessageBox::Cancel, QMessageBox::Cancel);
    if (reply != QMessageBox::Yes) return;

    QFile::remove(preferencesFilePath());

    m_topN           = 10;
    m_useBytes       = FALSE;
    m_useMAC         = FALSE;
    m_ntopEnabled    = true;
    m_malcolmEnabled = false;

    if (m_top10Btn)  m_top10Btn->setChecked(true);
    if (m_top25Btn)  m_top25Btn->setChecked(false);
    if (m_top50Btn)  m_top50Btn->setChecked(false);
    if (m_packetsBtn) m_packetsBtn->setChecked(true);
    if (m_bytesBtn)   m_bytesBtn->setChecked(false);
    if (m_ipBtn)  m_ipBtn->setChecked(true);
    if (m_macBtn) m_macBtn->setChecked(false);
    if (m_circleBtn) m_circleBtn->setChecked(true);
    if (m_tableBtn)  m_tableBtn->setChecked(false);
    if (m_viewStack) m_viewStack->setCurrentIndex(0);
    if (m_lineThicknessCheckBox) m_lineThicknessCheckBox->setChecked(false);
    updateSearchBarForMode();

    if (m_sendToNtopBtn)    m_sendToNtopBtn->setVisible(true);
    if (m_sendToMalcolmBtn) m_sendToMalcolmBtn->setVisible(false);

    m_enableL2Analysis     = true;
    m_enableTransportStats = true;
    m_enableDeepInspection = true;

    resize(1280, 780);

    m_thresholdGroups.clear();
    m_thresholdGroups.append(GraphWidget::GraphThresholds::defaults());
    m_thresholdGroups.append(GraphWidget::GraphThresholds::strict());
    m_thresholdGroups.append(GraphWidget::GraphThresholds::tolerant());
    m_activeThresholdGroup = 0;
    if (m_graphWidget) m_graphWidget->setThresholds(m_thresholdGroups[0]);

    m_wifiThresholdGroups.clear();
    m_wifiThresholdGroups.append(CircleWidget::WifiThresholds::defaults());
    m_activeWifiThresholdGroup = 0;
    if (m_circleWidget) m_circleWidget->setWifiThresholds(m_wifiThresholdGroups[0]);
    updateLegend();

    savePreferences();
    QMessageBox::information(this, "Reset Complete", "Settings have been reset to defaults.");
}

/* ── About sub-dialog ───────────────────────────────────────────────────── */
void MainWindow::showAboutDialog()
{
    bool dark = isDarkTheme();
    QDialog dlg(this);
    dlg.setWindowTitle(QString("About PacketCircle %1").arg(QLatin1String(PC_VERSION)));
    dlg.setMinimumWidth(460);

    if (dark) {
        dlg.setStyleSheet(
            "QDialog { background:#1e1e1e; color:#e0e0e0; }"
            "QLabel { color:#e0e0e0; }"
            "QGroupBox { color:#e0e0e0; border:1px solid #444; border-radius:4px; margin-top:8px; }"
            "QGroupBox::title { subcontrol-origin:margin; left:10px; padding:0 4px; color:#90caf9; }"
            "QPushButton { background:#333; color:#e0e0e0; border:1px solid #555; padding:4px 14px; border-radius:3px; }"
            "QPushButton:hover:enabled { background:#444; }");
    }

    QVBoxLayout *main = new QVBoxLayout(&dlg);
    main->setSpacing(8);
    main->setContentsMargins(14, 10, 14, 10);

    QGroupBox *aboutGrp = new QGroupBox("About");
    QVBoxLayout *aboutBox = new QVBoxLayout(aboutGrp);
    aboutBox->setSpacing(5);

    const QString platform =
#if defined(Q_OS_MACOS)
        "macOS Universal";
#elif defined(Q_OS_LINUX)
        "Linux x86_64";
#elif defined(Q_OS_WIN)
        "Windows x86_64";
#else
        "Unknown platform";
#endif

    QLabel *verLabel = new QLabel(
        QString("<b>PacketCircle %1</b> &nbsp;&middot;&nbsp; %2 &nbsp;&middot;&nbsp; Qt %3")
        .arg(QLatin1String(PC_VERSION), platform, QLatin1String(QT_VERSION_STR)));
    verLabel->setTextFormat(Qt::RichText);
    aboutBox->addWidget(verLabel);

    QStringList pluginSearchPaths = {
        QDir::homePath() + "/.local/lib/wireshark/plugins/4-6/epan/packetcircle.so",
        QDir::homePath() + "/.local/lib/wireshark/plugins/4.6/epan/packetcircle.so",
#if defined(Q_OS_WIN)
        QDir::fromNativeSeparators(qEnvironmentVariable("APPDATA"))
            + "/Wireshark/plugins/4.6/epan/packetcircle.dll",
        QDir::fromNativeSeparators(qEnvironmentVariable("APPDATA"))
            + "/Wireshark/plugins/4-6/epan/packetcircle.dll",
        QDir::fromNativeSeparators(qEnvironmentVariable("LOCALAPPDATA"))
            + "/Wireshark/plugins/4.6/epan/packetcircle.dll",
        QDir::fromNativeSeparators(qEnvironmentVariable("LOCALAPPDATA"))
            + "/Wireshark/plugins/4-6/epan/packetcircle.dll",
        "C:/Program Files/Wireshark/plugins/4.6/epan/packetcircle.dll",
        "C:/Program Files/Wireshark/plugins/4-6/epan/packetcircle.dll",
#endif
    };
    QString foundPluginPath;
    for (const QString &pp : pluginSearchPaths)
        if (QFile::exists(pp)) { foundPluginPath = pp; break; }

    QLabel *pathLabel = new QLabel(
        foundPluginPath.isEmpty()
        ? QString("<span style='color:%1;'>&#9888; Plugin file not found at expected location</span>")
            .arg(dark ? "#f0c040" : "#b07800")
        : QString("<span style='color:%1;'>&#10003; %2</span>")
            .arg(dark ? "#6ec96e" : "#27ae60", foundPluginPath.toHtmlEscaped()));
    pathLabel->setTextFormat(Qt::RichText);
    pathLabel->setWordWrap(true);
    aboutBox->addWidget(pathLabel);

    QHBoxLayout *updateRow = new QHBoxLayout;
    QPushButton *checkUpdateBtn  = new QPushButton("Check for Updates");
    QLabel      *updateStatusLbl = new QLabel("");
    updateStatusLbl->setTextFormat(Qt::RichText);
    updateStatusLbl->setOpenExternalLinks(true);
    updateRow->addWidget(checkUpdateBtn);
    updateRow->addWidget(updateStatusLbl, 1);
    aboutBox->addLayout(updateRow);

    main->addWidget(aboutGrp);
    main->addStretch();

    QHBoxLayout *btnRow = new QHBoxLayout;
    btnRow->addStretch();
    QPushButton *closeBtn = new QPushButton("Close");
    btnRow->addWidget(closeBtn);
    main->addLayout(btnRow);

    QObject::connect(checkUpdateBtn, &QPushButton::clicked,
                     [this, checkUpdateBtn, updateStatusLbl]() {
        QPointer<QPushButton> safeBtn(checkUpdateBtn);
        QPointer<QLabel>      safeLbl(updateStatusLbl);

        if (safeBtn) safeBtn->setEnabled(false);
        if (safeLbl) safeLbl->setText("Checking…");

        if (!m_networkManager)
            m_networkManager = new QNetworkAccessManager(this);

        QNetworkRequest req(QUrl("https://api.github.com/repos/netwho/PacketCircle/releases/latest"));
        req.setHeader(QNetworkRequest::UserAgentHeader, QString("PacketCircle/%1").arg(QLatin1String(PC_VERSION + 2)));
        req.setRawHeader("Accept", "application/vnd.github.v3+json");

        QNetworkReply *reply = m_networkManager->get(req);
        QObject::connect(reply, &QNetworkReply::finished,
                         [reply, safeBtn, safeLbl]() mutable {
            reply->deleteLater();
            if (safeBtn) safeBtn->setEnabled(true);
            if (!safeLbl) return;

            if (reply->error() != QNetworkReply::NoError) {
                safeLbl->setText(
                    QString("<span style='color:#e07070;'>Could not reach GitHub (%1)</span>")
                    .arg(reply->errorString().toHtmlEscaped()));
                return;
            }

            QString tag = QJsonDocument::fromJson(reply->readAll())
                              .object().value("tag_name").toString();
            if (tag.isEmpty()) {
                safeLbl->setText("<span style='color:#e07070;'>No release info found</span>");
                return;
            }

            auto strip = [](const QString &s) {
                QString r = s.toLower();
                if (r.startsWith("v.")) return r.mid(2);
                if (r.startsWith("v"))  return r.mid(1);
                return r;
            };
            auto isNewer = [&](const QString &remote, const QString &current) {
                auto parts = [](const QString &v) {
                    QList<int> out;
                    for (const QString &p : v.split('.'))
                        out.append(p.toInt());
                    while (out.size() < 3) out.append(0);
                    return out;
                };
                QList<int> r = parts(remote), c = parts(current);
                for (int i = 0; i < 3; i++) {
                    if (r[i] > c[i]) return true;
                    if (r[i] < c[i]) return false;
                }
                return false;
            };

            if (!isNewer(strip(tag), strip(QString(PC_VERSION)))) {
                safeLbl->setText("<span style='color:#6ec96e;'>&#10003; Up to date</span>");
            } else {
                static const QString dlUrl =
                    "https://raw.githubusercontent.com/netwho/PacketCircle/main/installer.zip";
                auto reply2 = QMessageBox::question(
                    nullptr, "Update Available",
                    QString("PacketCircle %1 is available (you have %2).\n\nDownload installer.zip now?")
                    .arg(tag, QLatin1String(PC_VERSION)),
                    QMessageBox::Yes | QMessageBox::No, QMessageBox::Yes);
                if (reply2 == QMessageBox::Yes)
                    QDesktopServices::openUrl(QUrl(dlUrl));
                safeLbl->setText(
                    QString("<span style='color:#f0c040;'>%1 available</span>")
                    .arg(tag.toHtmlEscaped()));
            }
        });
    });

    QObject::connect(closeBtn, &QPushButton::clicked, &dlg, &QDialog::accept);
    dlg.exec();
}


/* ── Graph threshold group persistence ──────────────────────────────────────
 * Groups are stored in the same INI file.
 * Keys: thresholds/count, thresholds/N/name, thresholds/N/hs_pkt_large, …   */
void MainWindow::saveThresholdGroups()
{
    QSettings settings(preferencesFilePath(), QSettings::IniFormat);
    /* Start at 3 — indices 0-2 (Default/Strict/Tolerant) are built-in, never written */
    settings.beginWriteArray("thresholds");
    int writeIdx = 0;
    for (int i = 3; i < m_thresholdGroups.size(); i++) {
        settings.setArrayIndex(writeIdx++);
        const auto &t = m_thresholdGroups[i];
        settings.setValue("name",                   t.name);
        settings.setValue("hs_pkt_large",           t.hs_pkt_large);
        settings.setValue("hs_pkt_moderate",        t.hs_pkt_moderate);
        settings.setValue("hs_pkt_small",           t.hs_pkt_small);
        settings.setValue("hs_pkt_tiny",            t.hs_pkt_tiny);
        settings.setValue("hs_pkt_very_few",        t.hs_pkt_very_few);
        settings.setValue("hs_pkt_few",             t.hs_pkt_few);
        settings.setValue("hs_pkt_sustained",       t.hs_pkt_sustained);
        settings.setValue("hs_ports_high",          t.hs_ports_high);
        settings.setValue("hs_ports_elevated",      t.hs_ports_elevated);
        settings.setValue("rt_fast_ms",             t.rt_fast_ms);
        settings.setValue("rt_moderate_ms",         t.rt_moderate_ms);
        settings.setValue("rt_slow_ms",             t.rt_slow_ms);
        settings.setValue("rt_very_slow_ms",        t.rt_very_slow_ms);
        settings.setValue("an_ports_critical",      t.an_ports_critical);
        settings.setValue("an_ports_high",          t.an_ports_high);
        settings.setValue("an_ports_elevated",      t.an_ports_elevated);
        settings.setValue("an_ports_slight",        t.an_ports_slight);
        settings.setValue("an_scan_min_ports",      t.an_scan_min_ports);
        settings.setValue("an_scan_ppp",            t.an_scan_ppp);
        settings.setValue("an_flood_tiny_pkt",      t.an_flood_tiny_pkt);
        settings.setValue("an_flood_tiny_count",    t.an_flood_tiny_count);
        settings.setValue("an_flood_small_pkt",     t.an_flood_small_pkt);
        settings.setValue("an_flood_small_count",   t.an_flood_small_count);
        settings.setValue("an_oneway_count",        t.an_oneway_count);
    }
    settings.endArray();
}

void MainWindow::loadThresholdGroups()
{
    QSettings settings(preferencesFilePath(), QSettings::IniFormat);
    /* Always keep built-in profiles at indices 0-2 */
    m_thresholdGroups.clear();
    m_thresholdGroups.append(GraphWidget::GraphThresholds::defaults());
    m_thresholdGroups.append(GraphWidget::GraphThresholds::strict());
    m_thresholdGroups.append(GraphWidget::GraphThresholds::tolerant());

    int count = settings.beginReadArray("thresholds");
    for (int i = 0; i < count; i++) {
        settings.setArrayIndex(i);
        GraphWidget::GraphThresholds t = GraphWidget::GraphThresholds::defaults();
        t.name                 = settings.value("name", QString("Group %1").arg(i+1)).toString();
        t.hs_pkt_large         = settings.value("hs_pkt_large",         t.hs_pkt_large).toInt();
        t.hs_pkt_moderate      = settings.value("hs_pkt_moderate",      t.hs_pkt_moderate).toInt();
        t.hs_pkt_small         = settings.value("hs_pkt_small",         t.hs_pkt_small).toInt();
        t.hs_pkt_tiny          = settings.value("hs_pkt_tiny",          t.hs_pkt_tiny).toInt();
        t.hs_pkt_very_few      = settings.value("hs_pkt_very_few",      t.hs_pkt_very_few).toInt();
        t.hs_pkt_few           = settings.value("hs_pkt_few",           t.hs_pkt_few).toInt();
        t.hs_pkt_sustained     = settings.value("hs_pkt_sustained",     t.hs_pkt_sustained).toInt();
        t.hs_ports_high        = settings.value("hs_ports_high",        t.hs_ports_high).toInt();
        t.hs_ports_elevated    = settings.value("hs_ports_elevated",    t.hs_ports_elevated).toInt();
        t.rt_fast_ms           = settings.value("rt_fast_ms",           t.rt_fast_ms).toInt();
        t.rt_moderate_ms       = settings.value("rt_moderate_ms",       t.rt_moderate_ms).toInt();
        t.rt_slow_ms           = settings.value("rt_slow_ms",           t.rt_slow_ms).toInt();
        t.rt_very_slow_ms      = settings.value("rt_very_slow_ms",      t.rt_very_slow_ms).toInt();
        t.an_ports_critical    = settings.value("an_ports_critical",    t.an_ports_critical).toInt();
        t.an_ports_high        = settings.value("an_ports_high",        t.an_ports_high).toInt();
        t.an_ports_elevated    = settings.value("an_ports_elevated",    t.an_ports_elevated).toInt();
        t.an_ports_slight      = settings.value("an_ports_slight",      t.an_ports_slight).toInt();
        t.an_scan_min_ports    = settings.value("an_scan_min_ports",    t.an_scan_min_ports).toInt();
        t.an_scan_ppp          = settings.value("an_scan_ppp",          t.an_scan_ppp).toDouble();
        t.an_flood_tiny_pkt    = settings.value("an_flood_tiny_pkt",    t.an_flood_tiny_pkt).toInt();
        t.an_flood_tiny_count  = settings.value("an_flood_tiny_count",  t.an_flood_tiny_count).toInt();
        t.an_flood_small_pkt   = settings.value("an_flood_small_pkt",   t.an_flood_small_pkt).toInt();
        t.an_flood_small_count = settings.value("an_flood_small_count", t.an_flood_small_count).toInt();
        t.an_oneway_count      = settings.value("an_oneway_count",      t.an_oneway_count).toInt();
        m_thresholdGroups.append(t);
    }
    settings.endArray();
}

/* ── WiFi threshold group save / load ───────────────────────────────────── */
void MainWindow::saveWifiThresholdGroups()
{
    QSettings settings(preferencesFilePath(), QSettings::IniFormat);
    settings.beginWriteArray("wifiThresholds");
    int writeIdx = 0;
    for (int i = 1; i < m_wifiThresholdGroups.size(); i++) {   /* skip index 0 (Default, builtIn) */
        settings.setArrayIndex(writeIdx++);
        const auto &t = m_wifiThresholdGroups[i];
        settings.setValue("name",           t.name);
        settings.setValue("rssi_excellent", t.rssi_excellent);
        settings.setValue("rssi_good",      t.rssi_good);
        settings.setValue("rssi_fair",      t.rssi_fair);
    }
    settings.endArray();
}

void MainWindow::loadWifiThresholdGroups()
{
    QSettings settings(preferencesFilePath(), QSettings::IniFormat);
    m_wifiThresholdGroups.clear();
    m_wifiThresholdGroups.append(CircleWidget::WifiThresholds::defaults()); /* index 0 always Default */

    int count = settings.beginReadArray("wifiThresholds");
    for (int i = 0; i < count; i++) {
        settings.setArrayIndex(i);
        CircleWidget::WifiThresholds t = CircleWidget::WifiThresholds::defaults();
        t.name           = settings.value("name", QString("Group %1").arg(i + 1)).toString();
        t.builtIn        = false;
        t.rssi_excellent = settings.value("rssi_excellent", t.rssi_excellent).toInt();
        t.rssi_good      = settings.value("rssi_good",      t.rssi_good).toInt();
        t.rssi_fair      = settings.value("rssi_fair",      t.rssi_fair).toInt();
        m_wifiThresholdGroups.append(t);
    }
    settings.endArray();
}

/* ── WiFi threshold group editor dialog ─────────────────────────────────────
 * groupName.isEmpty() → create new group (cloned from Default).
 * Otherwise, edit the existing group with that name.                         */
void MainWindow::showWifiThresholdGroupEditor(const QString &groupName)
{
    int editIdx = -1;
    CircleWidget::WifiThresholds working = CircleWidget::WifiThresholds::defaults();
    bool isNew = groupName.isEmpty();

    if (!isNew) {
        for (int i = 0; i < m_wifiThresholdGroups.size(); i++) {
            if (m_wifiThresholdGroups[i].name == groupName) { editIdx = i; working = m_wifiThresholdGroups[i]; break; }
        }
        if (editIdx < 0) return;
    } else {
        working.name    = "New Group";
        working.builtIn = false;
    }

    bool isBuiltIn = (!isNew && working.builtIn);

    QDialog dlg(this);
    dlg.setWindowTitle(isNew ? "Add WiFi Threshold Group"
                             : (isBuiltIn ? QString("View — %1 (read-only)").arg(working.name)
                                          : "Edit WiFi Threshold Group"));
    dlg.setMinimumWidth(400);

    QVBoxLayout *main = new QVBoxLayout(&dlg);
    main->setSpacing(8);
    main->setContentsMargins(12, 12, 12, 12);

    /* Group name */
    QHBoxLayout *nameRow = new QHBoxLayout;
    QLineEdit *nameEdit = new QLineEdit(working.name);
    nameEdit->setReadOnly(isBuiltIn);
    nameRow->addWidget(new QLabel("Group name:"));
    nameRow->addWidget(nameEdit, 1);
    main->addLayout(nameRow);

    /* Threshold spinboxes */
    QGroupBox *thGrp = new QGroupBox("RSSI Thresholds (dBm)");
    QFormLayout *thForm = new QFormLayout(thGrp);
    thForm->setSpacing(6);

    auto addSpin = [&](const QString &label, int val) -> QSpinBox* {
        QSpinBox *sb = new QSpinBox;
        sb->setRange(-100, 0);
        sb->setSuffix(" dBm");
        sb->setValue(val);
        sb->setReadOnly(isBuiltIn);
        sb->setButtonSymbols(isBuiltIn ? QAbstractSpinBox::NoButtons : QAbstractSpinBox::UpDownArrows);
        thForm->addRow(label, sb);
        return sb;
    };

    QLabel *hint = new QLabel("Signal bins: Excellent ≥ excellent_threshold, Good ≥ good_threshold,\n"
                               "Fair ≥ fair_threshold, Poor below fair_threshold.\n"
                               "Thresholds must be strictly descending (excellent > good > fair).");
    hint->setWordWrap(true);
    hint->setStyleSheet("color: gray; font-size: 8pt;");
    thForm->addRow(hint);

    QSpinBox *sbExcellent = addSpin("Excellent threshold (≥ X → Excellent):", working.rssi_excellent);
    QSpinBox *sbGood      = addSpin("Good threshold (≥ X → Good):",           working.rssi_good);
    QSpinBox *sbFair      = addSpin("Fair threshold (≥ X → Fair):",            working.rssi_fair);
    main->addWidget(thGrp);

    QDialogButtonBox *bbx;
    if (isBuiltIn)
        bbx = new QDialogButtonBox(QDialogButtonBox::Close);
    else
        bbx = new QDialogButtonBox(QDialogButtonBox::Save | QDialogButtonBox::Cancel);
    main->addWidget(bbx);

    if (!isBuiltIn) {
        QObject::connect(bbx, &QDialogButtonBox::accepted, [&]() {
            int exc = sbExcellent->value();
            int gd  = sbGood->value();
            int fr  = sbFair->value();
            if (!(exc > gd && gd > fr)) {
                QMessageBox::warning(&dlg, "Invalid Thresholds",
                    "Thresholds must be strictly descending:\n"
                    "Excellent > Good > Fair\n\n"
                    "Example: Excellent -60, Good -65, Fair -70");
                return;
            }
            working.name           = nameEdit->text().trimmed();
            if (working.name.isEmpty()) working.name = "Unnamed";
            if (working.name == "Default") working.name += " (copy)";
            working.builtIn        = false;
            working.rssi_excellent = exc;
            working.rssi_good      = gd;
            working.rssi_fair      = fr;

            if (isNew) {
                m_wifiThresholdGroups.append(working);
                m_activeWifiThresholdGroup = m_wifiThresholdGroups.size() - 1;
            } else {
                m_wifiThresholdGroups[editIdx] = working;
            }
            if (m_circleWidget && (isNew || editIdx == m_activeWifiThresholdGroup))
                m_circleWidget->setWifiThresholds(working);
            dlg.accept();
        });
    }

    QObject::connect(bbx, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);
    dlg.exec();
}

/* ── Threshold group editor dialog ──────────────────────────────────────────
 * groupName.isEmpty() → create new group (cloned from Default).
 * Otherwise, edit the existing group with that name.                         */
void MainWindow::showThresholdGroupEditor(const QString &groupName)
{
    /* Find the group to edit (or prepare a new one) */
    int editIdx = -1;
    GraphWidget::GraphThresholds working = GraphWidget::GraphThresholds::defaults();
    bool isNew = groupName.isEmpty();

    if (!isNew) {
        for (int i = 0; i < m_thresholdGroups.size(); i++) {
            if (m_thresholdGroups[i].name == groupName) { editIdx = i; working = m_thresholdGroups[i]; break; }
        }
        if (editIdx < 0) return;
    } else {
        working.name = "New Group";
        working.builtIn = false;
    }

    bool isBuiltIn = (!isNew && working.builtIn);

    QDialog dlg(this);
    dlg.setWindowTitle(isNew ? "Add Threshold Group" : (isBuiltIn ? QString("View — %1 (read-only)").arg(working.name) : "Edit Threshold Group"));
    dlg.setMinimumWidth(480);
    dlg.setSizeGripEnabled(true);

    QVBoxLayout *main = new QVBoxLayout(&dlg);
    main->setSpacing(8);
    main->setContentsMargins(12, 12, 12, 12);

    /* Group name */
    QHBoxLayout *nameRow = new QHBoxLayout;
    QLineEdit *nameEdit = new QLineEdit(working.name);
    nameEdit->setReadOnly(isBuiltIn);
    nameRow->addWidget(new QLabel("Group name:"));
    nameRow->addWidget(nameEdit, 1);
    main->addLayout(nameRow);

    /* Helper: add a labelled int spinbox row */
    auto addInt = [&](QFormLayout *form, const QString &label, int val, int lo, int hi, bool readOnly) -> QSpinBox* {
        QSpinBox *sb = new QSpinBox;
        sb->setRange(lo, hi);
        sb->setValue(val);
        sb->setReadOnly(readOnly);
        sb->setButtonSymbols(readOnly ? QAbstractSpinBox::NoButtons : QAbstractSpinBox::UpDownArrows);
        form->addRow(label, sb);
        return sb;
    };
    auto addDbl = [&](QFormLayout *form, const QString &label, double val, double lo, double hi, bool readOnly) -> QDoubleSpinBox* {
        QDoubleSpinBox *sb = new QDoubleSpinBox;
        sb->setRange(lo, hi);
        sb->setDecimals(1);
        sb->setSingleStep(0.5);
        sb->setValue(val);
        sb->setReadOnly(readOnly);
        sb->setButtonSymbols(readOnly ? QAbstractSpinBox::NoButtons : QAbstractSpinBox::UpDownArrows);
        form->addRow(label, sb);
        return sb;
    };

    /* ── TCP Health section ── */
    QGroupBox *hsGrp = new QGroupBox("TCP Health Signals");
    QFormLayout *hsForm = new QFormLayout(hsGrp);
    hsForm->setSpacing(4);
    auto *sb_hs_pkt_large      = addInt(hsForm, "Large packet size (B) — threshold for +25%:", working.hs_pkt_large,     50, 9999, isBuiltIn);
    auto *sb_hs_pkt_moderate   = addInt(hsForm, "Moderate packet size (B) — +15%:",             working.hs_pkt_moderate,  20, 9999, isBuiltIn);
    auto *sb_hs_pkt_small      = addInt(hsForm, "Small packet size (B) — +5%:",                 working.hs_pkt_small,     10, 9999, isBuiltIn);
    auto *sb_hs_pkt_tiny       = addInt(hsForm, "Tiny packet size (B) — -30%:",                 working.hs_pkt_tiny,       1,  500, isBuiltIn);
    auto *sb_hs_pkt_very_few   = addInt(hsForm, "Very few packets — -20%:",                     working.hs_pkt_very_few,   1,  100, isBuiltIn);
    auto *sb_hs_pkt_few        = addInt(hsForm, "Few packets — -10%:",                          working.hs_pkt_few,        1,  100, isBuiltIn);
    auto *sb_hs_pkt_sustained  = addInt(hsForm, "Sustained packets — +10%:",                    working.hs_pkt_sustained,  5, 9999, isBuiltIn);
    auto *sb_hs_ports_high     = addInt(hsForm, "High port diversity — -25%:",                  working.hs_ports_high,     1,  100, isBuiltIn);
    auto *sb_hs_ports_elevated = addInt(hsForm, "Elevated port diversity — -10%:",              working.hs_ports_elevated, 1,   50, isBuiltIn);
    main->addWidget(hsGrp);

    /* ── Response Time section ── */
    QGroupBox *rtGrp = new QGroupBox("Response Time Bins (ms)");
    QFormLayout *rtForm = new QFormLayout(rtGrp);
    rtForm->setSpacing(4);
    auto *sb_rt_fast_ms       = addInt(rtForm, "Fast — green threshold (ms):",       working.rt_fast_ms,      1, 9999, isBuiltIn);
    auto *sb_rt_moderate_ms   = addInt(rtForm, "Moderate — yellow-green limit (ms):", working.rt_moderate_ms,  1, 9999, isBuiltIn);
    auto *sb_rt_slow_ms       = addInt(rtForm, "Slow — yellow limit (ms):",           working.rt_slow_ms,      1, 9999, isBuiltIn);
    auto *sb_rt_very_slow_ms  = addInt(rtForm, "Very slow — orange limit (ms):",      working.rt_very_slow_ms, 1, 9999, isBuiltIn);
    rtForm->addRow(new QLabel("Above orange limit → red (unacceptable)"));
    main->addWidget(rtGrp);

    /* ── Anomaly Score section ── */
    QGroupBox *anGrp = new QGroupBox("Anomaly Score Signals");
    QFormLayout *anForm = new QFormLayout(anGrp);
    anForm->setSpacing(4);
    auto *sb_an_ports_critical   = addInt(anForm, "Critical port diversity — +50%:",    working.an_ports_critical,   1,  500, isBuiltIn);
    auto *sb_an_ports_high       = addInt(anForm, "High port diversity — +35%:",        working.an_ports_high,       1,  200, isBuiltIn);
    auto *sb_an_ports_elevated   = addInt(anForm, "Elevated port diversity — +20%:",    working.an_ports_elevated,   1,  100, isBuiltIn);
    auto *sb_an_ports_slight     = addInt(anForm, "Slight port diversity — +8%:",       working.an_ports_slight,     1,   50, isBuiltIn);
    auto *sb_an_scan_min_ports   = addInt(anForm, "Min ports to check scan rate:",      working.an_scan_min_ports,   1,   50, isBuiltIn);
    auto *sb_an_scan_ppp         = addDbl(anForm, "Scan: max pkts/port ratio — +20%:",  working.an_scan_ppp,       0.1, 50.0, isBuiltIn);
    auto *sb_an_flood_tiny_pkt   = addInt(anForm, "Flood: tiny packet size (B) — +25%:",working.an_flood_tiny_pkt,   1,  500, isBuiltIn);
    auto *sb_an_flood_tiny_count = addInt(anForm, "Flood: min packets (tiny) — +25%:", working.an_flood_tiny_count,  1, 9999, isBuiltIn);
    auto *sb_an_flood_small_pkt  = addInt(anForm, "Flood: small packet size (B) — +10%:",working.an_flood_small_pkt, 1,  500, isBuiltIn);
    auto *sb_an_flood_small_count= addInt(anForm, "Flood: min packets (small) — +10%:",working.an_flood_small_count, 1, 9999, isBuiltIn);
    auto *sb_an_oneway_count     = addInt(anForm, "One-way exfil min packets — +15%:",  working.an_oneway_count,     1, 9999, isBuiltIn);
    main->addWidget(anGrp);

    /* Buttons */
    QDialogButtonBox *bbx;
    if (isBuiltIn)
        bbx = new QDialogButtonBox(QDialogButtonBox::Close);
    else
        bbx = new QDialogButtonBox(QDialogButtonBox::Save | QDialogButtonBox::Cancel);
    main->addWidget(bbx);

    if (!isBuiltIn) {
        QObject::connect(bbx, &QDialogButtonBox::accepted, [&]() {
            /* Collect values */
            working.name                  = nameEdit->text().trimmed();
            if (working.name.isEmpty()) working.name = "Unnamed";
            if (working.name == "Default" || working.name == "Strict" || working.name == "Tolerant")
                working.name += " (copy)";
            working.builtIn               = false;
            working.hs_pkt_large          = sb_hs_pkt_large->value();
            working.hs_pkt_moderate       = sb_hs_pkt_moderate->value();
            working.hs_pkt_small          = sb_hs_pkt_small->value();
            working.hs_pkt_tiny           = sb_hs_pkt_tiny->value();
            working.hs_pkt_very_few       = sb_hs_pkt_very_few->value();
            working.hs_pkt_few            = sb_hs_pkt_few->value();
            working.hs_pkt_sustained      = sb_hs_pkt_sustained->value();
            working.hs_ports_high         = sb_hs_ports_high->value();
            working.hs_ports_elevated     = sb_hs_ports_elevated->value();
            working.rt_fast_ms            = sb_rt_fast_ms->value();
            working.rt_moderate_ms        = sb_rt_moderate_ms->value();
            working.rt_slow_ms            = sb_rt_slow_ms->value();
            working.rt_very_slow_ms       = sb_rt_very_slow_ms->value();
            working.an_ports_critical     = sb_an_ports_critical->value();
            working.an_ports_high         = sb_an_ports_high->value();
            working.an_ports_elevated     = sb_an_ports_elevated->value();
            working.an_ports_slight       = sb_an_ports_slight->value();
            working.an_scan_min_ports     = sb_an_scan_min_ports->value();
            working.an_scan_ppp           = sb_an_scan_ppp->value();
            working.an_flood_tiny_pkt     = sb_an_flood_tiny_pkt->value();
            working.an_flood_tiny_count   = sb_an_flood_tiny_count->value();
            working.an_flood_small_pkt    = sb_an_flood_small_pkt->value();
            working.an_flood_small_count  = sb_an_flood_small_count->value();
            working.an_oneway_count       = sb_an_oneway_count->value();

            if (isNew) {
                m_thresholdGroups.append(working);
                m_activeThresholdGroup = m_thresholdGroups.size() - 1;
            } else {
                m_thresholdGroups[editIdx] = working;
            }
            /* Apply immediately if this is the active group */
            if (!isNew && editIdx == m_activeThresholdGroup && m_graphWidget)
                m_graphWidget->setThresholds(working);
            if (isNew && m_graphWidget)
                m_graphWidget->setThresholds(working);

            dlg.accept();
        });
    }

    QObject::connect(bbx, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);
    dlg.exec();
}

void MainWindow::onSendToNtopClicked()
{
    /* 1. Get capture file path via bridge */
    const char *path_c = circle_vis_get_capture_filename();
    if (!path_c) {
        QMessageBox::warning(this, "Send to NTOP",
            "No capture file is currently loaded.\nPlease open a PCAP file in Wireshark first.");
        return;
    }
    QString capturePath = QString::fromUtf8(path_c);
    g_free((gpointer)path_c);

    /* 2. Check file size (ntopng limit: 25 MB) */
    QFileInfo fi(capturePath);
    if (!fi.exists()) {
        QMessageBox::warning(this, "Send to NTOP",
            QString("Capture file not found:\n%1").arg(capturePath));
        return;
    }
    const qint64 NTOP_MAX_BYTES = 26214400LL; /* 25 MB */
    if (fi.size() > NTOP_MAX_BYTES) {
        QMessageBox::warning(this, "Send to NTOP",
            QString("Capture file is %1 MB — ntopng has a 25 MB upload limit.\n\n"
                    "Consider applying a display filter first, then saving a filtered copy.")
                .arg(fi.size() / 1048576));
        return;
    }

    /* 3. Load ntopng settings */
    QSettings settings(preferencesFilePath(), QSettings::IniFormat);
    settings.beginGroup("ntopng");
    QString host          = settings.value("host", "").toString();
    int     port          = settings.value("port", 3001).toInt();
    bool    useHttps      = settings.value("use_https", true).toBool();
    QString username      = settings.value("username", "").toString();
    QString password      = settings.value("password", "").toString();
    bool    ignoreSsl     = settings.value("ignore_ssl_errors", true).toBool();
    QString caCertPath    = settings.value("ca_cert_path", "").toString();
    settings.endGroup();

    /* 4. Prompt for config if missing */
    if (host.isEmpty() || username.isEmpty()) {
        if (!showNtopngConfigDialog()) return;
        settings.beginGroup("ntopng");
        host       = settings.value("host", "").toString();
        port       = settings.value("port", 3001).toInt();
        useHttps   = settings.value("use_https", true).toBool();
        username   = settings.value("username", "").toString();
        password   = settings.value("password", "").toString();
        ignoreSsl  = settings.value("ignore_ssl_errors", true).toBool();
        caCertPath = settings.value("ca_cert_path", "").toString();
        settings.endGroup();
    }

    if (host.isEmpty() || username.isEmpty()) {
        QMessageBox::warning(this, "Send to NTOP",
            "Please configure ntopng host and credentials first.\n\n"
            "Tip: Right-click the 'Send to NTOP' button to open settings.");
        return;
    }

    /* 5. Upload */
    m_sendToNtopBtn->setEnabled(false);
    m_sendToNtopBtn->setText("Uploading...");
    uploadToNtopng(capturePath, host, port, useHttps, username, password, ignoreSsl, caCertPath);
}

void MainWindow::uploadToNtopng(const QString &filePath, const QString &host, int port,
                                 bool useHttps, const QString &username, const QString &password,
                                 bool ignoreSslErrors, const QString &caCertPath)
{
    static const QString NTOP_TIP =
        "\n\nTip: Right-click the 'Send to NTOP' button to reconfigure settings.";

    QString scheme  = useHttps ? "https" : "http";
    QString baseUrl = QString("%1://%2:%3").arg(scheme, host).arg(port);
    QUrl uploadUrl(baseUrl + "/lua/rest/v2/add/ntopng/analyze_pcap.lua?create_new_interface=true");

    /* Read the entire capture file into memory (25 MB guard applied above). */
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) {
        QMessageBox::warning(this, "Send to NTOP",
            QString("Cannot read capture file:\n%1%2").arg(filePath, NTOP_TIP));
        m_sendToNtopBtn->setEnabled(true);
        m_sendToNtopBtn->setText("Send to NTOP");
        return;
    }
    QByteArray fileData = file.readAll();
    file.close();

    /* Build the multipart body manually as a single QByteArray.
     *
     * QHttpMultiPart falls back to Transfer-Encoding: chunked even when all
     * part bodies are in-memory, because it streams through an internal device.
     * ntopng's embedded HTTP server (mongoose) does not support chunked
     * incoming bodies: it reads until the parser stalls, returns 400, and the
     * remaining bytes are misinterpreted as a second HTTP request — producing
     * the doubled response seen in the logs.
     *
     * By building the body ourselves and posting a plain QByteArray we force
     * Qt to set Content-Length and never use chunked encoding. */
    /* Filename includes a short datetime stamp so each capture gets its own
     * slot on ntopng (e.g. "PacketCircle-20260316-143022.pcap").
     * The 500 fallback still reuses an existing interface if the exact same
     * filename was already uploaded in this session. */
    QString safeFilename = QStringLiteral("PacketCircle-") +
                           QDateTime::currentDateTime().toString("yyyyMMdd-HHmmss") +
                           QStringLiteral(".pcap");
    QByteArray boundary = "----PacketCircleBoundary" +
                          QByteArray::number(QDateTime::currentMSecsSinceEpoch());
    QByteArray body;
    body += "--" + boundary + "\r\n";
    body += "Content-Disposition: form-data; name=\"pcap_file\"; filename=\""
            + safeFilename.toUtf8() + "\"\r\n";
    body += "\r\n";
    body += fileData;
    body += "\r\n--" + boundary + "--\r\n";

    /* Build request with Basic Auth */
    QNetworkRequest request(uploadUrl);
    QByteArray credentials = (username + ":" + password).toUtf8().toBase64();
    request.setRawHeader("Authorization", "Basic " + credentials);
    request.setHeader(QNetworkRequest::ContentTypeHeader,
        "multipart/form-data; boundary=" + boundary);
    request.setHeader(QNetworkRequest::ContentLengthHeader, body.size());

    /* SSL configuration */
    QSslConfiguration sslConf = QSslConfiguration::defaultConfiguration();
    /* Accept TLS 1.0+ so we negotiate with whatever the server offers */
    sslConf.setProtocol(QSsl::TlsV1_2OrLater);
    if (!caCertPath.isEmpty()) {
        QList<QSslCertificate> certs = QSslCertificate::fromPath(caCertPath);
        if (!certs.isEmpty()) {
            sslConf.addCaCertificates(certs);
            qDebug() << "[NTOP] Loaded" << certs.size() << "CA cert(s) from" << caCertPath;
        } else {
            qDebug() << "[NTOP] WARNING: No certificates loaded from" << caCertPath;
        }
    }
    if (ignoreSslErrors)
        sslConf.setPeerVerifyMode(QSslSocket::VerifyNone);
    request.setSslConfiguration(sslConf);

    if (!m_networkManager)
        m_networkManager = new QNetworkAccessManager(this);

    qDebug() << "[NTOP] POST" << uploadUrl.toString()
             << "| file:" << filePath
             << "| user:" << username
             << "| ignoreSsl:" << ignoreSslErrors
             << "| caCert:" << (caCertPath.isEmpty() ? "(none)" : caCertPath);

    QNetworkReply *reply = m_networkManager->post(request, body);

    /* ignoreSslErrors() MUST be called synchronously right after post(),
     * before the event loop runs — calling it inside the sslErrors signal
     * lambda is too late and the handshake will have already been aborted. */
    if (ignoreSslErrors)
        reply->ignoreSslErrors();

    /* SSL error logging (for diagnostics even when ignoring) */
    connect(reply, &QNetworkReply::sslErrors, reply,
        [ignoreSslErrors](const QList<QSslError> &errors) {
            qDebug() << "[NTOP] SSL errors" << (ignoreSslErrors ? "(ignored):" : "(NOT ignored — check cert):");
            for (const QSslError &e : errors)
                qDebug() << "  " << e.errorString();
        });

    connect(reply, &QNetworkReply::finished, this,
        [this, reply, uploadUrl, baseUrl, safeFilename, sslConf, credentials, ignoreSslErrors]() {
        reply->deleteLater();
        m_sendToNtopBtn->setEnabled(true);
        m_sendToNtopBtn->setText("Send to NTOP");

        static const QString NTOP_TIP =
            "\n\nTip: Right-click the 'Send to NTOP' button to reconfigure settings.";

        int httpStatus = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        QByteArray responseData = reply->readAll();

        qDebug() << "[NTOP] HTTP status:" << httpStatus;
        qDebug() << "[NTOP] Network error code:" << reply->error()
                 << reply->errorString();
        qDebug() << "[NTOP] Response body:" << responseData.left(1000);

        /* ---- Parse the JSON body (present even on HTTP error responses) ---- */
        QJsonObject respObj;
        QJsonDocument respDoc = QJsonDocument::fromJson(responseData);
        if (!respDoc.isNull() && respDoc.isObject())
            respObj = respDoc.object();

        QString rcStr = respObj["rc_str"].toString();

        /* ---- 500 INTERNAL_ERROR = "same pcap already uploaded" ------------- */
        if (httpStatus == 500 && rcStr == "INTERNAL_ERROR") {
            qDebug() << "[NTOP] PCAP already uploaded — looking up existing interface for:" << safeFilename;

            QUrl ifacesUrl(baseUrl + "/lua/rest/v2/get/ntopng/interfaces.lua");
            QNetworkRequest ifaceReq(ifacesUrl);
            ifaceReq.setRawHeader("Authorization", "Basic " + credentials);
            ifaceReq.setSslConfiguration(sslConf);

            QNetworkReply *ifaceReply = m_networkManager->get(ifaceReq);
            if (ignoreSslErrors)
                ifaceReply->ignoreSslErrors();

            connect(ifaceReply, &QNetworkReply::finished, this,
                [this, ifaceReply, baseUrl, safeFilename, sslConf, credentials, ignoreSslErrors]() {
                ifaceReply->deleteLater();

                static const QString NTOP_TIP =
                    "\n\nTip: Right-click the 'Send to NTOP' button to reconfigure settings.";

                QJsonDocument ifDoc = QJsonDocument::fromJson(ifaceReply->readAll());
                if (!ifDoc.isNull() && ifDoc.isObject()) {
                    const QJsonArray ifaces = ifDoc.object()["rsp"].toArray();
                    for (const QJsonValue &v : ifaces) {
                        QJsonObject iface = v.toObject();
                        if (iface["is_pcap_interface"].toBool() &&
                            iface["name"].toString() == safeFilename) {
                            int ifid = iface["ifid"].toInt(-1);
                            if (ifid >= 0) {
                                /* Activate the interface */
                                QUrl activateUrl(
                                    QString("%1/lua/rest/v2/set/ntopng/active_interface.lua?ifid=%2")
                                    .arg(baseUrl).arg(ifid));
                                QNetworkRequest activateReq(activateUrl);
                                activateReq.setRawHeader("Authorization", "Basic " + credentials);
                                activateReq.setSslConfiguration(sslConf);
                                QNetworkReply *actReply = m_networkManager->get(activateReq);
                                if (ignoreSslErrors)
                                    actReply->ignoreSslErrors();
                                connect(actReply, &QNetworkReply::finished,
                                        actReply, &QObject::deleteLater);
                                qDebug() << "[NTOP] Sent activate request for existing ifid" << ifid;

                                /* Open the Apps (nDPI) page */
                                QString resultsUrl =
                                    QString("%1/lua/if_stats.lua?ifid=%2&page=ndpi")
                                    .arg(baseUrl).arg(ifid);
                                qDebug() << "[NTOP] Found existing ifid" << ifid << "— opening:" << resultsUrl;
                                QDesktopServices::openUrl(QUrl(resultsUrl));
                                return;
                            }
                        }
                    }
                }
                /* Interface not found in list */
                QMessageBox::warning(this, "Send to NTOP",
                    QString("This PCAP was already uploaded to ntopng but its interface "
                            "could not be found in the interface list.\n\n"
                            "File: %1%2").arg(safeFilename, NTOP_TIP));
            });
            return;
        }

        /* ---- Generic HTTP error ------------------------------------------- */
        if (reply->error() != QNetworkReply::NoError) {
            QString ntopMsg = respObj["rc_str_hr"].toString();
            if (ntopMsg.isEmpty()) ntopMsg = rcStr;
            if (ntopMsg.isEmpty()) ntopMsg = QString::fromUtf8(responseData.left(200));

            QMessageBox::warning(this, "Send to NTOP",
                QString("Upload failed (HTTP %1):\n%2\n\nntopng says: %3\n\nURL: %4%5")
                    .arg(httpStatus)
                    .arg(reply->errorString())
                    .arg(ntopMsg)
                    .arg(uploadUrl.toString())
                    .arg(NTOP_TIP));
            return;
        }

        /* ---- Unexpected non-JSON response ---------------------------------- */
        if (respObj.isEmpty()) {
            QMessageBox::warning(this, "Send to NTOP",
                QString("Unexpected response from ntopng (HTTP %1).\n\nURL: %2\n\nResponse:\n%3%4")
                    .arg(httpStatus)
                    .arg(uploadUrl.toString())
                    .arg(QString::fromUtf8(responseData.left(300)))
                    .arg(NTOP_TIP));
            return;
        }

        /* ---- ntopng-level error (rc != 0) ---------------------------------- */
        int rc = respObj["rc"].toInt(-1);
        qDebug() << "[NTOP] JSON rc:" << rc << "| rsp:" << respObj["rsp"];
        if (rc != 0) {
            QString errMsg = respObj["rc_str_hr"].toString();
            if (errMsg.isEmpty()) errMsg = rcStr;
            QMessageBox::warning(this, "Send to NTOP",
                QString("ntopng returned an error (rc=%1):\n%2%3")
                    .arg(rc).arg(errMsg).arg(NTOP_TIP));
            return;
        }

        /* ---- Success ------------------------------------------------------- */
        int ifid = respObj["rsp"].toObject()["new_ifid"].toInt(-1);
        if (ifid < 0) {
            qDebug() << "[NTOP] rsp object:" << respObj["rsp"];
            QMessageBox::warning(this, "Send to NTOP",
                QString("ntopng accepted the file but returned an invalid interface ID.\n\nrsp: %1%2")
                    .arg(QString::fromUtf8(QJsonDocument(respObj["rsp"].toObject()).toJson()))
                    .arg(NTOP_TIP));
            return;
        }

        /* Activate the new interface so ntopng starts processing it */
        QUrl activateUrl(QString("%1/lua/rest/v2/set/ntopng/active_interface.lua?ifid=%2")
                         .arg(baseUrl).arg(ifid));
        QNetworkRequest activateReq(activateUrl);
        activateReq.setRawHeader("Authorization", "Basic " + credentials);
        activateReq.setSslConfiguration(sslConf);
        QNetworkReply *actReply = m_networkManager->get(activateReq);
        if (ignoreSslErrors)
            actReply->ignoreSslErrors();
        connect(actReply, &QNetworkReply::finished, actReply, &QObject::deleteLater);
        qDebug() << "[NTOP] Sent activate request for ifid" << ifid;

        /* Open the Apps (nDPI protocol breakdown) page for the new interface */
        QString resultsUrl = QString("%1/lua/if_stats.lua?ifid=%2&page=ndpi")
                             .arg(baseUrl).arg(ifid);
        qDebug() << "[NTOP] Success! Opening:" << resultsUrl;
        QDesktopServices::openUrl(QUrl(resultsUrl));
    });
}

/* ══════════════════════════════════════════════════════════════════════════
 * Malcolm / Arkime Integration
 * ══════════════════════════════════════════════════════════════════════════ */

/* Read first/last packet timestamps from a pcapng file.
 * Handles Section Header Blocks (SHB), Interface Description Blocks (IDB),
 * and Enhanced Packet Blocks (EPB, type 0x00000006).
 * Respects the if_tsresol option in IDBs; default resolution is microseconds. */
static bool pcapng_read_timestamps(QFile &f, bool swapped,
                                   quint32 *startTime, quint32 *stopTime)
{
    auto rd16 = [&](const uchar *p) -> quint16 {
        if (swapped)
            return ((quint16)p[0] << 8) | (quint16)p[1];
        return (quint16)p[0] | ((quint16)p[1] << 8);
    };
    auto rd32 = [&](const uchar *p) -> quint32 {
        if (swapped)
            return ((quint32)p[0]<<24)|((quint32)p[1]<<16)|((quint32)p[2]<<8)|(quint32)p[3];
        return (quint32)p[0]|((quint32)p[1]<<8)|((quint32)p[2]<<16)|((quint32)p[3]<<24);
    };

    /* Default timestamp resolution: microseconds (10^-6) */
    quint64 ts_divisor = 1000000ULL;

    quint32 first = 0, last = 0;
    bool found = false;

    while (!f.atEnd()) {
        /* Every block starts with: block_type(4) + block_total_length(4) */
        QByteArray blk_hdr = f.read(8);
        if (blk_hdr.size() < 8) break;

        const uchar *bh    = (const uchar *)blk_hdr.constData();
        quint32 block_type = rd32(bh);
        quint32 block_len  = rd32(bh + 4);

        /* Minimum valid block = type(4)+len(4)+trailing_len(4) = 12 bytes */
        if (block_len < 12 || block_len > 256*1024*1024) break;

        quint32 body_len = block_len - 12; /* excludes type+len+trailing_len */

        if (block_type == 0x0a0d0d0a) {
            /* Section Header Block — skip body + trailing length */
            if (!f.seek(f.pos() + body_len + 4)) break;

        } else if (block_type == 0x00000001) {
            /* Interface Description Block — scan options for if_tsresol (opt 9) */
            QByteArray body = f.read(body_len);
            if ((quint32)body.size() < body_len) break;
            /* Fixed IDB header: LinkType(2) + Reserved(2) + SnapLen(4) = 8 bytes */
            if (body_len > 8) {
                const uchar *opt = (const uchar *)body.constData() + 8;
                int remaining    = (int)body_len - 8;
                while (remaining >= 4) {
                    quint16 opt_code = rd16(opt);
                    quint16 opt_len  = rd16(opt + 2);
                    if (opt_code == 0) break; /* opt_endofopt */
                    quint32 padded = (opt_len + 3) & ~3u;
                    if (remaining < (int)(4 + padded)) break;
                    if (opt_code == 9 && opt_len == 1) {
                        /* if_tsresol: bit7=0 → power of 10, bit7=1 → power of 2 */
                        uchar resol = opt[4];
                        if (resol & 0x80) {
                            ts_divisor = (quint64)1 << (resol & 0x7F);
                        } else {
                            ts_divisor = 1;
                            int exp = resol & 0x7F;
                            for (int i = 0; i < exp; i++) ts_divisor *= 10;
                        }
                        if (ts_divisor == 0) ts_divisor = 1; /* guard */
                    }
                    opt       += 4 + padded;
                    remaining -= (int)(4 + padded);
                }
            }
            if (!f.seek(f.pos() + 4)) break; /* trailing block_total_length */

        } else if (block_type == 0x00000006) {
            /* Enhanced Packet Block:
             * Interface ID(4) + Timestamp High(4) + Timestamp Low(4) +
             * Captured Len(4) + Original Len(4) + packet data + options */
            if (body_len < 20) { f.seek(f.pos() + body_len + 4); continue; }
            QByteArray epb = f.read(20);
            if (epb.size() < 20) break;
            const uchar *b = (const uchar *)epb.constData();
            quint32 ts_hi  = rd32(b + 4);
            quint32 ts_lo  = rd32(b + 8);
            quint64 ts64   = ((quint64)ts_hi << 32) | ts_lo;
            quint32 ts_sec = (quint32)(ts64 / ts_divisor);

            if (!found) { first = ts_sec; found = true; }
            last = ts_sec;

            /* skip remaining body bytes + trailing block_total_length */
            if (!f.seek(f.pos() + (body_len - 20) + 4)) break;

        } else {
            /* All other block types — skip body + trailing length */
            if (!f.seek(f.pos() + body_len + 4)) break;
        }
    }

    if (!found) return false;
    *startTime = first;
    *stopTime  = last;
    return true;
}

/* Read the first and last packet timestamps from a PCAP or pcapng file.
 * Returns true if at least one packet was found; sets *startTime and
 * *stopTime to Unix epoch seconds.  Supports little-endian and big-endian
 * classic PCAP as well as pcapng (magic 0x0a0d0d0a). */
static bool pcap_read_timestamps(const QString &path,
                                 quint32 *startTime, quint32 *stopTime)
{
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly))
        return false;

    /* Read only the global header first (24 bytes) */
    QByteArray hdr = f.read(24);
    if (hdr.size() < 24) { f.close(); return false; }

    const uchar *h = (const uchar *)hdr.constData();
    quint32 magic = (quint32)h[0] | ((quint32)h[1]<<8) |
                    ((quint32)h[2]<<16) | ((quint32)h[3]<<24);

    bool swapped = false;
    if (magic == 0xa1b2c3d4 || magic == 0xa1b23c4d) {
        swapped = false; /* little-endian PCAP (native on x86/arm) */
    } else if (magic == 0xd4c3b2a1 || magic == 0x4d3cb2a1) {
        swapped = true;  /* big-endian PCAP */
    } else if (magic == 0x0a0d0d0a) {
        /* pcapng — byte-order magic is at offset 8 within the SHB */
        quint32 bom = (quint32)h[8] | ((quint32)h[9]<<8) |
                      ((quint32)h[10]<<16) | ((quint32)h[11]<<24);
        bool ng_swapped = (bom != 0x1a2b3c4d);
        f.seek(0);
        bool ok = pcapng_read_timestamps(f, ng_swapped, startTime, stopTime);
        f.close();
        return ok;
    } else {
        f.close(); return false; /* unknown format */
    }

    auto le32 = [&](const uchar *p) -> quint32 {
        return (quint32)p[0] | ((quint32)p[1]<<8) |
               ((quint32)p[2]<<16) | ((quint32)p[3]<<24);
    };
    auto be32 = [&](const uchar *p) -> quint32 {
        return ((quint32)p[0]<<24) | ((quint32)p[1]<<16) |
               ((quint32)p[2]<<8)  | (quint32)p[3];
    };
    auto rd32 = [&](const uchar *p) -> quint32 {
        return swapped ? be32(p) : le32(p);
    };

    quint32 first = 0, last = 0;
    bool found = false;

    /* Stream packet records without loading the whole file */
    while (!f.atEnd()) {
        QByteArray rechdr = f.read(16);
        if (rechdr.size() < 16) break;
        const uchar *r = (const uchar *)rechdr.constData();
        quint32 ts_sec  = rd32(r);      /* seconds since epoch */
        quint32 incl_len = rd32(r + 8); /* captured length     */

        if (incl_len > 65536) break;    /* sanity &mdash; corrupt data */

        if (!found) { first = ts_sec; found = true; }
        last = ts_sec;

        /* Skip packet data */
        f.seek(f.pos() + incl_len);
    }
    f.close();

    if (!found) return false;
    *startTime = first;
    *stopTime  = last;
    return true;
}

bool MainWindow::showMalcolmConfigDialog()
{
    bool dark = isDarkTheme();
    QDialog dlg(this);
    dlg.setWindowTitle("Configure Malcolm / Arkime");
    dlg.setMinimumWidth(400);

    if (dark) {
        dlg.setStyleSheet(
            "QDialog { background:#1e1e1e; color:#e0e0e0; }"
            "QLabel  { color:#e0e0e0; }"
            "QLineEdit { background:#2d2d2d; color:#e0e0e0; border:1px solid #555; padding:3px; }"
            "QCheckBox { color:#e0e0e0; }"
            "QPushButton { background:#333; color:#e0e0e0; border:1px solid #555;"
            "  padding:4px 14px; border-radius:3px; }"
            "QPushButton:hover { background:#444; }"
        );
    }

    QSettings settings(preferencesFilePath(), QSettings::IniFormat);
    settings.beginGroup("malcolm");
    QString savedHost    = settings.value("host",             "").toString();
    int     savedPort    = settings.value("port",             443).toInt();
    bool    savedHttps   = settings.value("use_https",        true).toBool();
    QString savedUser    = settings.value("username",         "").toString();
    QString savedPass    = settings.value("password",         "").toString();
    bool    savedIgnSsl  = settings.value("ignore_ssl_errors",true).toBool();
    settings.endGroup();

    QVBoxLayout *main = new QVBoxLayout(&dlg);
    main->setSpacing(10);
    main->setContentsMargins(14, 12, 14, 12);

    QFormLayout *form = new QFormLayout;
    form->setFieldGrowthPolicy(QFormLayout::ExpandingFieldsGrow);

    QLineEdit *hostEdit = new QLineEdit(savedHost);
    hostEdit->setPlaceholderText("e.g. malcolm.example.com");
    form->addRow("Host:", hostEdit);

    QLineEdit *portEdit = new QLineEdit(QString::number(savedPort));
    portEdit->setPlaceholderText("443");
    form->addRow("Port:", portEdit);

    QCheckBox *httpsChk = new QCheckBox("Use HTTPS");
    httpsChk->setChecked(savedHttps);
    form->addRow("", httpsChk);

    QLineEdit *userEdit = new QLineEdit(savedUser);
    userEdit->setPlaceholderText("Malcolm username");
    form->addRow("Username:", userEdit);

    QLineEdit *passEdit = new QLineEdit(savedPass);
    passEdit->setEchoMode(QLineEdit::Password);
    passEdit->setPlaceholderText("Malcolm password");
    form->addRow("Password:", passEdit);

    QCheckBox *ignSslChk = new QCheckBox("Ignore SSL certificate errors");
    ignSslChk->setChecked(savedIgnSsl);
    ignSslChk->setToolTip("Enable for self-signed certificates (e.g. lab deployments)");
    form->addRow("", ignSslChk);

    main->addLayout(form);
    main->addSpacing(4);

    QDialogButtonBox *bb = new QDialogButtonBox(
        QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
    if (dark) {
        bb->setStyleSheet(
            "QPushButton { background:#333; color:#e0e0e0; border:1px solid #555;"
            "  padding:4px 14px; border-radius:3px; }"
            "QPushButton:hover { background:#444; }"
        );
    }
    main->addWidget(bb);

    QObject::connect(bb, &QDialogButtonBox::accepted, &dlg, &QDialog::accept);
    QObject::connect(bb, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);

    if (dlg.exec() != QDialog::Accepted)
        return false;

    QString host = hostEdit->text().trimmed();
    int     port = portEdit->text().toInt();
    if (port <= 0 || port > 65535) port = 443;

    settings.beginGroup("malcolm");
    settings.setValue("host",              host);
    settings.setValue("port",              port);
    settings.setValue("use_https",         httpsChk->isChecked());
    settings.setValue("username",          userEdit->text());
    settings.setValue("password",          passEdit->text());
    settings.setValue("ignore_ssl_errors", ignSslChk->isChecked());
    settings.endGroup();
    settings.sync();

    return !host.isEmpty();
}

void MainWindow::onSendToMalcolmClicked()
{
    /* 1. Get capture file path via bridge */
    const char *path_c = circle_vis_get_capture_filename();
    if (!path_c) {
        QMessageBox::warning(this, "Send to Malcolm",
            "No capture file is currently loaded.\n"
            "Please open a PCAP file in Wireshark first.");
        return;
    }
    QString capturePath = QString::fromUtf8(path_c);
    g_free((gpointer)path_c);

    /* 2. Verify file exists */
    QFileInfo fi(capturePath);
    if (!fi.exists()) {
        QMessageBox::warning(this, "Send to Malcolm",
            QString("Capture file not found:\n%1").arg(capturePath));
        return;
    }

    /* 3. Load Malcolm settings */
    QSettings settings(preferencesFilePath(), QSettings::IniFormat);
    settings.beginGroup("malcolm");
    QString host       = settings.value("host",             "").toString();
    int     port       = settings.value("port",             443).toInt();
    bool    useHttps   = settings.value("use_https",        true).toBool();
    QString username   = settings.value("username",         "").toString();
    QString password   = settings.value("password",         "").toString();
    bool    ignoreSsl  = settings.value("ignore_ssl_errors",true).toBool();
    settings.endGroup();

    /* 4. Prompt for configuration if not set */
    if (host.isEmpty() || username.isEmpty()) {
        int ret = QMessageBox::question(this, "Send to Malcolm",
            "Malcolm / Arkime is not yet configured.\n"
            "Open settings now?",
            QMessageBox::Yes | QMessageBox::Cancel,
            QMessageBox::Yes);
        if (ret != QMessageBox::Yes) return;
        if (!showMalcolmConfigDialog()) return;

        settings.beginGroup("malcolm");
        host      = settings.value("host",             "").toString();
        port      = settings.value("port",             443).toInt();
        useHttps  = settings.value("use_https",        true).toBool();
        username  = settings.value("username",         "").toString();
        password  = settings.value("password",         "").toString();
        ignoreSsl = settings.value("ignore_ssl_errors",true).toBool();
        settings.endGroup();

        if (host.isEmpty()) return;
    }

    /* 5. Extract first/last packet timestamps for Arkime filter.
     * Prefer the bridge function which reads from Wireshark's already-parsed
     * frame_data (guaranteed correct for all formats).  Fall back to the
     * file-based reader if the bridge is unavailable (e.g. cf already closed). */
    quint32 startTime = 0, stopTime = 0;
    bool hasTimestamps = (bool)circle_vis_get_capture_time_range(&startTime, &stopTime);
    if (!hasTimestamps)
        hasTimestamps = pcap_read_timestamps(capturePath, &startTime, &stopTime);
    if (!hasTimestamps) {
        qDebug() << "[MALCOLM] Could not extract PCAP timestamps from" << capturePath;
        /* Continue without timestamps — Arkime will open without a time filter */
    }

    /* 6. File-size check — Malcolm's PHP stack has strict upload limits.
     * The typical defaults are upload_max_filesize = 2 MB and
     * post_max_size = 8 MB.  Warn the user and suggest reducing the capture
     * before uploading rather than letting them wait only to receive a
     * silent HTTP 500 from the server. */
    {
        const qint64 WARN_BYTES = 8LL * 1024 * 1024;   /* 8 MB — PHP post_max_size */
        qint64 fileBytes = fi.size();
        double fileMb    = fileBytes / (1024.0 * 1024.0);

        if (fileBytes > WARN_BYTES) {
            int answer = QMessageBox::warning(this, "Send to Malcolm — Large File",
                QString(
                    "The capture file is <b>%1 MB</b>, which typically exceeds "
                    "Malcolm's PHP upload limit (8 MB by default).\n\n"
                    "The upload will likely fail.  To reduce the file size:\n\n"
                    "  1. Apply a Wireshark <b>display filter</b> to the packets you care about\n"
                    "     (e.g.  ip.addr == 192.168.1.0/24  or  tcp.port == 443)\n\n"
                    "  2. Go to  <b>File → Export Specified Packets</b>\n"
                    "     • Choose \"Displayed\" to export only the filtered packets\n"
                    "     • Save as a new .pcapng file\n\n"
                    "  3. Re-open that smaller file in Wireshark and click Send to Malcolm again.\n\n"
                    "Upload anyway?")
                    .arg(fileMb, 0, 'f', 1),
                QMessageBox::Yes | QMessageBox::No,
                QMessageBox::No);

            if (answer != QMessageBox::Yes)
                return;
        }
    }

    /* 7. Disable button and start upload */
    m_sendToMalcolmBtn->setEnabled(false);
    m_sendToMalcolmBtn->setText("Uploading...");
    uploadToMalcolm(capturePath, host, port, useHttps, username, password,
                    ignoreSsl, startTime, stopTime);
}

/* ── pcapng → pcap conversion helpers ───────────────────────────────────────
 * Arkime's capture-offline uses libpcap which rejects pcapng files that
 * contain multiple Interface Description Blocks (IDB) with different
 * snapshot lengths — common in files produced by mergecap or by capturing
 * on multiple interfaces simultaneously.  If editcap is available we convert
 * to classic libpcap (pcap) format, which capture-offline handles reliably.
 * ─────────────────────────────────────────────────────────────────────────── */

static bool isPcapng(const QString &path)
{
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) return false;
    QByteArray magic = f.read(4);
    f.close();
    /* pcapng Section Header Block magic: 0x0a0d0d0a */
    return magic.size() == 4
        && (unsigned char)magic[0] == 0x0a && (unsigned char)magic[1] == 0x0d
        && (unsigned char)magic[2] == 0x0d && (unsigned char)magic[3] == 0x0a;
}

static QString findEditcap()
{
    QStringList candidates;
#ifdef Q_OS_MAC
    candidates << "/Applications/Wireshark.app/Contents/MacOS/editcap";
#endif
#ifdef Q_OS_WIN
    candidates << "C:/Program Files/Wireshark/editcap.exe"
               << "C:/Program Files (x86)/Wireshark/editcap.exe";
#endif
    candidates << "editcap";   /* PATH fallback — works on Linux and WS-in-PATH */

    for (const QString &c : candidates) {
        QFileInfo fi(c);
        if (fi.isAbsolute()) {
            if (fi.exists() && fi.isExecutable()) return c;
        } else {
            QProcess which;
#ifdef Q_OS_WIN
            which.start("where", {c});
#else
            which.start("which", {c});
#endif
            which.waitForFinished(2000);
            if (which.exitCode() == 0)
                return c;
        }
    }
    return QString();
}

/* Convert pcapng to classic pcap in memory.  Returns converted bytes on
 * success, or an empty QByteArray if conversion is not needed or failed. */
static QByteArray pcapngToPcap(const QString &srcPath)
{
    if (!isPcapng(srcPath)) return QByteArray();

    QString editcap = findEditcap();
    if (editcap.isEmpty()) {
        qDebug() << "[MALCOLM] pcapng detected but editcap not found — uploading as-is";
        return QByteArray();
    }

    /* Write converted output to a temp file, then read it back */
    QTemporaryFile tmp(QDir::tempPath() + "/PacketCircle_upload_XXXXXX.pcap");
    tmp.setAutoRemove(false);   /* we delete manually after reading */
    if (!tmp.open()) return QByteArray();
    QString tmpPath = tmp.fileName();
    tmp.close();                /* editcap opens the file itself */

    QProcess proc;
    proc.start(editcap, {"-F", "pcap", srcPath, tmpPath});
    bool ok = proc.waitForFinished(30000) && proc.exitCode() == 0;

    QByteArray data;
    if (ok) {
        QFile f(tmpPath);
        if (f.open(QIODevice::ReadOnly)) {
            data = f.readAll();
            f.close();
        }
    } else {
        qDebug() << "[MALCOLM] editcap conversion failed (exit" << proc.exitCode() << "):"
                 << proc.readAllStandardError().trimmed();
    }
    QFile::remove(tmpPath);
    return data;
}

void MainWindow::uploadToMalcolm(const QString &filePath,
                                  const QString &host, int port,
                                  bool useHttps,
                                  const QString &username, const QString &password,
                                  bool ignoreSslErrors,
                                  quint32 startTime, quint32 stopTime)
{
    /*
     * Malcolm / Arkime uses the FilePond server-side PHP library for PCAP
     * uploads.  FilePond is a TWO-STEP protocol:
     *
     *   Step 1 — POST binary file to /upload/server/php/index.php
     *            Malcolm stores the file in a temp directory and returns a
     *            plain-text SERVER TOKEN (the temp filename / file-id).
     *
     *   Step 2 — POST token string (NOT the binary) + metadata to
     *            /upload/server/php/submit.php
     *            Malcolm moves the file into its PCAP processing queue,
     *            applies the tags, and Zeek/Suricata begin analysis.
     *
     * The previous implementation sent the binary file directly to submit.php.
     * submit.php expected a short text token, not raw binary, so it silently
     * discarded the payload — meaning the file was never actually queued for
     * processing and no sessions appeared in Arkime.
     */

    QString scheme       = useHttps ? "https" : "http";
    QString baseUrlClean = QString("%1://%2:%3").arg(scheme, host).arg(port);
    QByteArray credentials = (username + ":" + password).toUtf8().toBase64();

    /* Common SSL config shared across both requests */
    QSslConfiguration sslConf = QSslConfiguration::defaultConfiguration();
    sslConf.setProtocol(QSsl::TlsV1_2OrLater);
    if (ignoreSslErrors)
        sslConf.setPeerVerifyMode(QSslSocket::VerifyNone);

    /* Read the capture file — converting pcapng → classic pcap when possible.
     * Arkime's capture-offline rejects pcapng files with multiple IDB blocks
     * that have different snapshot lengths (e.g. mergecap output).  editcap
     * -F pcap produces a single-interface libpcap file that always works. */
    QByteArray fileData = pcapngToPcap(filePath);
    if (fileData.isEmpty()) {
        /* Not pcapng, or editcap unavailable — read file as-is */
        QFile file(filePath);
        if (!file.open(QIODevice::ReadOnly)) {
            QMessageBox::warning(this, "Send to Malcolm",
                QString("Cannot read capture file:\n%1").arg(filePath));
            m_sendToMalcolmBtn->setEnabled(true);
            m_sendToMalcolmBtn->setText("Send to Malcolm");
            return;
        }
        fileData = file.readAll();
        file.close();
    } else {
        qDebug() << "[MALCOLM] pcapng → pcap conversion: uploading" << fileData.size()
                 << "bytes (converted from pcapng)";
    }

    /* Timestamped filename so each upload is unique in Malcolm */
    QString safeFilename = QStringLiteral("PacketCircle-") +
                           QDateTime::currentDateTime().toString("yyyyMMdd-HHmmss") +
                           QStringLiteral(".pcap");

    if (!m_networkManager)
        m_networkManager = new QNetworkAccessManager(this);

    /* Wire authenticationRequired for NTLM/Digest challenge path */
    auto authConn = std::make_shared<QMetaObject::Connection>();
    *authConn = connect(m_networkManager, &QNetworkAccessManager::authenticationRequired,
        this, [username, password, authConn](QNetworkReply*, QAuthenticator *auth) {
            auth->setUser(username);
            auth->setPassword(password);
            QObject::disconnect(*authConn);
        });

    /* ── Step 1: POST the PCAP binary to /upload/server/php/index.php ──────
     * FilePond stores the file in a server-side temp directory and returns a
     * plain-text token we must send in Step 2.
     * -------------------------------------------------------------------- */
    QUrl step1Url;
    step1Url.setScheme(scheme);
    step1Url.setHost(host);
    step1Url.setPort(port);
    step1Url.setPath("/upload/server/php/");

    QByteArray boundary1 = "----MalcolmUploadBoundary" +
                           QByteArray::number(QDateTime::currentMSecsSinceEpoch());
    QByteArray step1Body;
    step1Body += "--" + boundary1 + "\r\n";
    step1Body += "Content-Disposition: form-data; name=\"filepond\"; filename=\""
                 + safeFilename.toUtf8() + "\"\r\n";
    step1Body += "Content-Type: application/vnd.tcpdump.pcap\r\n\r\n";
    step1Body += fileData;
    step1Body += "\r\n--" + boundary1 + "--\r\n";

    QNetworkRequest req1(step1Url);
    req1.setRawHeader("Authorization", "Basic " + credentials);
    req1.setHeader(QNetworkRequest::ContentTypeHeader,
                   "multipart/form-data; boundary=" + boundary1);
    req1.setHeader(QNetworkRequest::ContentLengthHeader, step1Body.size());
    req1.setAttribute(QNetworkRequest::RedirectPolicyAttribute,
                      QNetworkRequest::SameOriginRedirectPolicy);
    req1.setSslConfiguration(sslConf);

    qDebug() << "[MALCOLM] Step 1: POST" << fileData.size() << "bytes to"
             << baseUrlClean + "/upload/server/php/"
             << "| file:" << filePath << "| user:" << username
             << "| ignoreSsl:" << ignoreSslErrors
             << "| startTime:" << startTime << "stopTime:" << stopTime;

    QNetworkReply *reply1 = m_networkManager->post(req1, step1Body);

    if (ignoreSslErrors)
        reply1->ignoreSslErrors();

    connect(reply1, &QNetworkReply::sslErrors, reply1,
        [ignoreSslErrors](const QList<QSslError> &errors) {
            qDebug() << "[MALCOLM] Step 1 SSL errors"
                     << (ignoreSslErrors ? "(ignored):" : "(NOT ignored):");
            for (const QSslError &e : errors)
                qDebug() << "  " << e.errorString();
        });

    connect(reply1, &QNetworkReply::finished, this,
        [this, reply1, scheme, host, port, baseUrlClean,
         username, password, credentials, sslConf, ignoreSslErrors,
         startTime, stopTime]() {

        reply1->deleteLater();

        int status1        = reply1->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        QByteArray tokenRaw = reply1->readAll();
        QString fileToken   = QString::fromUtf8(tokenRaw).trimmed();

        qDebug() << "[MALCOLM] Step 1 HTTP status:" << status1;
        qDebug() << "[MALCOLM] Step 1 token:" << fileToken.left(200);

        if (reply1->error() != QNetworkReply::NoError || status1 < 200 || status1 >= 300) {
            m_sendToMalcolmBtn->setEnabled(true);
            m_sendToMalcolmBtn->setText("Send to Malcolm");
            QString hint = (status1 == 500 || status1 == 413)
                ? "\n\nHTTP 500/413 is usually caused by the capture file exceeding "
                  "Malcolm's PHP upload limit (upload_max_filesize or post_max_size).\n"
                  "Try reducing the file size:\n"
                  "  • Apply a display filter, then File \u2192 Export Specified Packets\n"
                  "  • Save as a smaller .pcapng and re-upload that file."
                : "\n\nCheck host, port, and credentials in Settings \u2699.";
            QMessageBox::warning(this, "Send to Malcolm",
                QString("File upload failed (HTTP %1):\n%2\n\n"
                        "URL: %3/upload/server/php/%4")
                    .arg(status1)
                    .arg(reply1->errorString())
                    .arg(baseUrlClean)
                    .arg(hint));
            return;
        }

        if (fileToken.isEmpty()) {
            m_sendToMalcolmBtn->setEnabled(true);
            m_sendToMalcolmBtn->setText("Send to Malcolm");
            QMessageBox::warning(this, "Send to Malcolm",
                "Malcolm accepted the file but returned an empty token.\n\n"
                "This usually means the file exceeded PHP's post_max_size limit (8 MB default).\n"
                "Try reducing the file size:\n"
                "  • Apply a display filter, then File \u2192 Export Specified Packets\n"
                "  • Save as a smaller .pcapng and re-upload that file.");
            return;
        }

        /* ── Step 2: POST token + tags to /upload/server/php/submit.php ────
         * The filepond field now carries the SERVER TOKEN (a short string),
         * not the binary file.  This tells Malcolm's backend to move the
         * already-stored temp file into the PCAP processing queue and apply
         * the supplied tags so Arkime labels every session "PacketCircle".
         * ---------------------------------------------------------------- */
        QUrl step2Url;
        step2Url.setScheme(scheme);
        step2Url.setHost(host);
        step2Url.setPort(port);
        step2Url.setPath("/upload/server/php/submit.php");

        QByteArray boundary2 = "----MalcolmSubmitBoundary" +
                               QByteArray::number(QDateTime::currentMSecsSinceEpoch());
        QByteArray step2Body;
        /* tags metadata field — Arkime labels every session from this upload */
        step2Body += "--" + boundary2 + "\r\n";
        step2Body += "Content-Disposition: form-data; name=\"tags\"\r\n\r\nPacketCircle\r\n";
        /* filepond[] token field — array notation required by FilePond PHP library.
         * route_form_post() checks for filepond[] (TRANSFER_IDS) specifically;
         * without the [] it finds no recognised payload type and falls through,
         * returning the upload HTML page instead of processing the transfer. */
        step2Body += "--" + boundary2 + "\r\n";
        step2Body += "Content-Disposition: form-data; name=\"filepond[]\"\r\n\r\n";
        step2Body += fileToken.toUtf8() + "\r\n";
        step2Body += "--" + boundary2 + "--\r\n";

        QNetworkRequest req2(step2Url);
        req2.setRawHeader("Authorization", "Basic " + credentials);
        req2.setHeader(QNetworkRequest::ContentTypeHeader,
                       "multipart/form-data; boundary=" + boundary2);
        req2.setHeader(QNetworkRequest::ContentLengthHeader, step2Body.size());
        req2.setAttribute(QNetworkRequest::RedirectPolicyAttribute,
                          QNetworkRequest::SameOriginRedirectPolicy);
        req2.setSslConfiguration(sslConf);

        qDebug() << "[MALCOLM] Step 2: POST token+tags to"
                 << baseUrlClean + "/upload/server/php/submit.php"
                 << "| token:" << fileToken;

        QNetworkReply *reply2 = m_networkManager->post(req2, step2Body);

        if (ignoreSslErrors)
            reply2->ignoreSslErrors();

        connect(reply2, &QNetworkReply::sslErrors, reply2,
            [ignoreSslErrors](const QList<QSslError> &errors) {
                qDebug() << "[MALCOLM] Step 2 SSL errors"
                         << (ignoreSslErrors ? "(ignored):" : "(NOT ignored):");
                for (const QSslError &e : errors)
                    qDebug() << "  " << e.errorString();
            });

        connect(reply2, &QNetworkReply::finished, this,
            [this, reply2, baseUrlClean, startTime, stopTime]() {

            reply2->deleteLater();
            m_sendToMalcolmBtn->setEnabled(true);
            m_sendToMalcolmBtn->setText("Send to Malcolm");

            int status2           = reply2->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
            QByteArray response2  = reply2->readAll();

            qDebug() << "[MALCOLM] Step 2 HTTP status:" << status2;
            qDebug() << "[MALCOLM] Step 2 response:" << response2.left(500);

            if (reply2->error() != QNetworkReply::NoError) {
                QMessageBox::warning(this, "Send to Malcolm",
                    QString("Malcolm submission failed (HTTP %1):\n%2\n\n"
                            "URL: %3/upload/server/php/submit.php\n\n"
                            "Check host, port, and credentials in Settings \u2699.")
                        .arg(status2)
                        .arg(reply2->errorString())
                        .arg(baseUrlClean));
                return;
            }

            /* Build Arkime sessions URL with PacketCircle tag filter + time window */
            QString expr = QUrl::toPercentEncoding("tags==PacketCircle");
            QString arkimeUrl;
            if (startTime > 0 && stopTime > 0) {
                /* Add a 60-second buffer each side for processing lag */
                quint32 t0 = (startTime > 60) ? startTime - 60 : 0;
                quint32 t1 = stopTime + 60;
                arkimeUrl = QString("%1/arkime/sessions?startTime=%2&stopTime=%3&expression=%4")
                                .arg(baseUrlClean).arg(t0).arg(t1).arg(expr);
            } else {
                arkimeUrl = QString("%1/arkime/sessions?expression=%2")
                                .arg(baseUrlClean, expr);
            }

            qDebug() << "[MALCOLM] Both steps complete. Opening Arkime:" << arkimeUrl;

            QMessageBox::information(this, "Send to Malcolm",
                QString("Upload complete!\n\n"
                        "Opening Arkime sessions view%1.\n\n"
                        "\u23f3  Malcolm processes uploaded PCAPs in the background \u2014 "
                        "it may take a minute before sessions appear.\n"
                        "If Arkime shows no results, wait ~60 seconds and reload the page.")
                    .arg(startTime > 0
                         ? QString(" filtered to the capture time window (%1 \u2013 %2)")
                               .arg(QDateTime::fromSecsSinceEpoch(startTime)
                                        .toString("yyyy-MM-dd HH:mm:ss"))
                               .arg(QDateTime::fromSecsSinceEpoch(stopTime)
                                        .toString("HH:mm:ss"))
                         : QString()));

            QDesktopServices::openUrl(QUrl(arkimeUrl));
        });
    });
}

void MainWindow::onReloadDataClicked()
{
    qDebug() << "MainWindow::onReloadDataClicked: Reloading data";
    circle_vis_reload_data();
}

void MainWindow::updateSearchBarForMode()
{
    if (!m_searchLineEdit) return;

    if (m_useMAC) {
        m_searchLineEdit->setPlaceholderText("Protocol or address  —  ? for help");
    } else {
        m_searchLineEdit->setPlaceholderText("Protocol, IP, CIDR, or port (TCP 443)  —  ? for help");
    }
    /* Clear current search when switching modes */
    m_searchLineEdit->clear();
}

bool MainWindow::isMACAddress(const QString &address)
{
    QStringList parts = address.split(':');
    if (parts.size() != 6) return false;
    for (const QString &p : parts) {
        if (p.length() != 2) return false;
    }
    return true;
}

/* Truncate a display string to a maximum character count, keeping
 * the beginning and end visible with "..." in between.
 * E.g. "very-long-hostname.example.com" → "very-l...le.com" */
static QString truncateDisplayName(const QString &name, int maxChars)
{
    if (name.length() <= maxChars || maxChars < 8)
        return name;
    int keepEnd = qMax(4, maxChars / 3);
    int keepStart = maxChars - keepEnd - 3;  /* 3 for "..." */
    if (keepStart < 3) keepStart = 3;
    return name.left(keepStart) + "..." + name.right(keepEnd);
}

void MainWindow::refreshPairListText()
{
    if (!m_pairListWidget || m_pairListWidget->count() == 0)
        return;

    /* Determine available width for text */
    int listWidth = m_pairListWidget->viewport()->width();
    QFontMetrics fm(m_pairListWidget->font());

    /* Reserve space for checkbox (~30px) + arrow (5 chars " <-> ") + safety margin */
    int reservedPx = fm.horizontalAdvance(" <-> ") + 50;
    int availablePx = listWidth - reservedPx;
    if (availablePx < 100) availablePx = 100;

    /* Calculate max characters that fit for each address column (half each) */
    int charWidth = fm.horizontalAdvance('W');  /* use a wide char for safety */
    if (charWidth < 1) charWidth = 8;
    int maxCharsPerAddr = (availablePx / 2) / charWidth;
    if (maxCharsPerAddr < 8) maxCharsPerAddr = 8;

    /* Build display strings for each item — apply truncation and measure for alignment */
    struct DisplayEntry {
        QString src;
        QString dst;
    };
    QVector<DisplayEntry> entries(m_pairListWidget->count());
    guint max_src_len = 0, max_dst_len = 0;

    for (int i = 0; i < m_pairListWidget->count(); i++) {
        QListWidgetItem *item = m_pairListWidget->item(i);
        comm_pair_t *pair = static_cast<comm_pair_t*>(item->data(Qt::UserRole).value<void*>());
        if (!pair || !pair->src_addr || !pair->dst_addr) continue;

        /* Use resolved names for display */
        QString src = pair->resolved_src ? QString::fromUtf8(pair->resolved_src) : QString::fromUtf8(pair->src_addr);
        QString dst = pair->resolved_dst ? QString::fromUtf8(pair->resolved_dst) : QString::fromUtf8(pair->dst_addr);

        /* Apply IPv6/MAC truncation first — skip in Wi-Fi mode to show full MACs */
        if (!m_wifiMode) {
            src = truncateIPv6Address(src);
            dst = truncateIPv6Address(dst);
        }

        /* Then truncate long names (hostnames, etc.) to fit the available width */
        src = truncateDisplayName(src, maxCharsPerAddr);
        dst = truncateDisplayName(dst, maxCharsPerAddr);

        entries[i].src = src;
        entries[i].dst = dst;
        if ((guint)src.length() > max_src_len) max_src_len = (guint)src.length();
        if ((guint)dst.length() > max_dst_len) max_dst_len = (guint)dst.length();
    }

    /* Update each item's text with aligned columns and direction-aware arrow */
    for (int i = 0; i < m_pairListWidget->count(); i++) {
        QListWidgetItem *item = m_pairListWidget->item(i);
        if (entries[i].src.isEmpty() && entries[i].dst.isEmpty()) continue;
        QString src = entries[i].src.leftJustified(max_src_len, ' ');
        QString dst = entries[i].dst.leftJustified(max_dst_len, ' ');
        int dir = item->data(Qt::UserRole + 2).toInt();
        const char *arrow = (dir == 1) ? " <-> "
                          : (dir == 2) ? " <-- "
                          :              " --> ";
        item->setText(src + QString::fromUtf8(arrow) + dst);
    }
}

QString MainWindow::truncateIPv6Address(const QString &address)
{
    /* Check if this is an IPv6 address (contains colons, not just dots) */
    if (!address.contains(':')) {
        /* IPv4 address - return as is */
        return address;
    }

    /* Check if this is a MAC address (exactly 6 groups of 2 hex chars, e.g., aa:bb:cc:dd:ee:ff) */
    QStringList mac_parts = address.split(':');
    if (mac_parts.size() == 6) {
        bool is_mac = true;
        for (const QString &p : mac_parts) {
            if (p.length() != 2) { is_mac = false; break; }
        }
        if (is_mac) {
            /* MAC address — return as-is; truncateDisplayName() handles
             * width-based truncation just like hostnames and IPv4 addresses. */
            return address;
        }
    }
    
    /* IPv6 address - extract first 4 hex digits and last 4 hex digits */
    /* Remove any leading/trailing brackets (e.g., [2001:db8::1]) */
    QString addr = address;
    if (addr.startsWith('[') && addr.endsWith(']')) {
        addr = addr.mid(1, addr.length() - 2);
    }

    /* Split by colons to get hex groups */
    QStringList parts = addr.split(':');
    if (parts.isEmpty()) {
        return address;  /* Invalid format, return original */
    }

    /* Validate that all groups are pure hex digits.
     * Vendor-resolved MAC names like "Cisco_a9:38:40" or "Apple_ab:cd:ef"
     * contain colons but have non-hex characters.  They must NOT go through
     * any truncation here — truncateDisplayName() handles them instead. */
    for (const QString &grp : parts) {
        if (grp.isEmpty()) continue;  /* :: compression produces empty groups */
        for (const QChar &c : grp) {
            if (!c.isDigit() && (c.toLower() < 'a' || c.toLower() > 'f')) {
                return address;  /* Not a real IPv6 address &mdash; return as-is */
            }
        }
    }

    /* Real IPv6 address — return as-is and let truncateDisplayName() shorten
     * it only when the panel is actually too narrow to show it in full.
     * This matches the behaviour for IPv4, MAC, and hostnames: the width-
     * aware pass in refreshPairListText() is the single place that decides
     * how much to show. */
    return address;
}

/* Extract raw MAC from a possibly resolved address like "Cisco_a9:38:40 (00:1b:2b:a9:38:40)" */
static QString stripResolvedAddr(const QString &addr)
{
    /* If it contains "(xx:xx:xx:xx:xx:xx)" or "(x.x.x.x)", grab inside parens */
    qsizetype lp = addr.lastIndexOf('(');
    qsizetype rp = addr.lastIndexOf(')');
    if (lp >= 0 && rp > lp + 1) {
        return addr.mid(lp + 1, rp - lp - 1);
    }
    return addr.trimmed();
}

QString MainWindow::createFilterString()
{
    if (!m_pairListWidget)
        return QString();

    /* Helper: build a bidirectional address filter clause.
     * ip.addr / eth.addr / wlan.addr match both src and dst, so a single
     * "ip.addr == X && ip.addr == Y" clause captures both directions. */
    auto makeBidir = [&](const QString &a, const QString &b) -> QString {
        if (m_wifiMode)
            return QString("(wlan.addr == %1 && wlan.addr == %2)").arg(a).arg(b);
        if (m_useMAC)
            return QString("(eth.addr == %1 && eth.addr == %2)").arg(a).arg(b);
        if (a.contains(':'))
            return QString("(ipv6.addr == %1 && ipv6.addr == %2)").arg(a).arg(b);
        return   QString("(ip.addr == %1 && ip.addr == %2)").arg(a).arg(b);
    };

    /* Helper: build a directional (src→dst) filter clause — used only when
     * the user explicitly chose a one-way arrow (dir 0 or dir 2). */
    auto makeDir = [&](const QString &src, const QString &dst) -> QString {
        if (m_wifiMode)
            return QString("(wlan.src == %1 && wlan.dst == %2)").arg(src).arg(dst);
        if (m_useMAC)
            return QString("(eth.src == %1 && eth.dst == %2)").arg(src).arg(dst);
        if (src.contains(':'))
            return QString("(ipv6.src == %1 && ipv6.dst == %2)").arg(src).arg(dst);
        return   QString("(ip.src == %1 && ip.dst == %2)").arg(src).arg(dst);
    };

    /* If specific pairs were selected via the circle widget, always bidirectional */
    if (!m_selectedPairs.isEmpty()) {
        QStringList filters;
        for (comm_pair_t *pair : m_selectedPairs) {
            QString a = stripResolvedAddr(QString::fromUtf8(pair->src_addr));
            QString b = stripResolvedAddr(QString::fromUtf8(pair->dst_addr));
            filters << makeBidir(a, b);
        }
        return filters.join(" || ");
    }

    /* Normal path: use checked list items, honouring the arrow direction state.
     *   dir 0 (⇒) — forward only  → directional ip.src/ip.dst filter
     *   dir 1 (⇔) — both dirs     → single bidirectional ip.addr filter
     *   dir 2 (⇐) — reverse only  → directional ip.src/ip.dst (reversed) filter */
    QStringList filters;
    for (int i = 0; i < m_pairListWidget->count(); i++) {
        QListWidgetItem *list_item = m_pairListWidget->item(i);
        if (!list_item || list_item->checkState() != Qt::Checked)
            continue;

        comm_pair_t *primary   = (comm_pair_t*)list_item->data(Qt::UserRole).value<void*>();
        comm_pair_t *secondary = (comm_pair_t*)list_item->data(Qt::UserRole + 1).value<void*>();
        int dir = list_item->data(Qt::UserRole + 2).toInt();

        if (dir == 1 || !secondary) {
            /* Bidirectional (or only one direction exists): emit one addr== clause */
            if (!primary) continue;
            QString a = stripResolvedAddr(QString::fromUtf8(primary->src_addr));
            QString b = stripResolvedAddr(QString::fromUtf8(primary->dst_addr));
            filters << makeBidir(a, b);
        } else {
            /* Directional arrow chosen: use src/dst to honour user intent */
            comm_pair_t *pair = (dir == 2) ? secondary : primary;
            if (!pair) continue;
            QString src = stripResolvedAddr(QString::fromUtf8(pair->src_addr));
            QString dst = stripResolvedAddr(QString::fromUtf8(pair->dst_addr));
            filters << makeDir(src, dst);
        }
    }
    return filters.join(" || ");
}

QList<comm_pair_t*> MainWindow::getActivePairsForFilter() const
{
    if (!m_selectedPairs.isEmpty()) {
        return m_selectedPairs;
    }

    QList<comm_pair_t*> active_pairs;
    if (!m_pairListWidget)
        return active_pairs;

    for (int i = 0; i < m_pairListWidget->count(); i++) {
        QListWidgetItem *list_item = m_pairListWidget->item(i);
        if (!list_item)
            continue;
        if (list_item->checkState() != Qt::Checked)
            continue;
        comm_pair_t *pair = (comm_pair_t *)list_item->data(Qt::UserRole).value<void*>();
        if (pair) {
            active_pairs.append(pair);
        }
    }

    return active_pairs;
}

void MainWindow::onPairListBlinkTimer()
{
    m_pairListBlinkState = !m_pairListBlinkState;
    if (m_highlightedPairItems.isEmpty()) {
        m_pairListBlinkTimer->stop();
        return;
    }

    for (int idx : m_highlightedPairItems) {
        QListWidgetItem *item = m_pairListWidget->item(idx);
        if (!item) continue;

        if (m_pairListBlinkState) {
            /* Blink ON: bright red background + white text (matches circle) */
            item->setBackground(QBrush(QColor(255, 0, 0)));
            item->setForeground(QBrush(QColor(255, 255, 255)));
            QFont f = item->font();
            f.setBold(true);
            item->setFont(f);
        } else {
            /* Blink OFF: restore normal appearance */
            item->setBackground(QBrush());
            item->setForeground(QBrush());
            QFont f = item->font();
            f.setBold(false);
            item->setFont(f);
        }
    }
}

/* ============================================================
 * showSearchHelp() — modal dialog with mode-specific search
 * keyword reference.  Called by typing "?" in the search bar
 * or when an invalid query is submitted.
 * ============================================================ */
void MainWindow::showSearchHelp()
{
    bool dark = m_darkTheme;
    QString bg   = dark ? "#1e1e1e" : "#ffffff";
    QString fg   = dark ? "#e0e0e0" : "#222222";
    QString head = dark ? "#90caf9" : "#1565c0";
    QString key  = dark ? "#c8e6c9" : "#1b5e20";
    QString dim  = dark ? "#aaaaaa" : "#666666";

    QString html = QString("<div style='background:%1; color:%2; font-size:12px;'>").arg(bg).arg(fg);

    /* Helper lambda — one table row (keyword | description) */
    auto krow = [&](const QString &kw, const QString &desc) -> QString {
        return QString("<tr>"
                       "<td style='font-family:monospace; color:%1; min-width:170px; "
                       "padding:2px 8px 2px 0;'><b>%2</b></td>"
                       "<td style='color:%3; padding:2px 0;'>%4</td>"
                       "</tr>").arg(key, kw.toHtmlEscaped(), dim, desc);
    };

    if (m_wifiMode) {
        /* ---- Wi-Fi mode ---- */
        html += QString("<h3 style='color:%1; margin:4px 0;'>Search Options &mdash; Wi-Fi Mode</h3>").arg(head);
        html += "<table cellpadding='0' cellspacing='0'>";
        html += krow("excellent",         "RSSI &ge; &minus;55 dBm");
        html += krow("good",              "RSSI &minus;65 to &minus;56 dBm");
        html += krow("fair",              "RSSI &minus;75 to &minus;66 dBm");
        html += krow("poor",              "RSSI &le; &minus;76 dBm");
        html += krow("ap  /  bssid",      "Highlight all access-point nodes");
        html += krow("MyNetwork",         "Partial SSID match (any text)");
        html += krow("aa:bb:cc",          "Partial BSSID / MAC address match");
        html += "</table>";

    } else if (!m_useMAC) {
        /* ---- IP mode ---- */
        html += QString("<h3 style='color:%1; margin:4px 0;'>Search Options &mdash; IP Mode</h3>").arg(head);

        html += QString("<p style='color:%1; margin:6px 0 2px 0;'><b>Protocol categories</b>"
                        " (press Enter):</p>").arg(head);
        html += "<table cellpadding='0' cellspacing='0'>";
        html += krow("ARP",                  "ARP / RARP broadcasts");
        html += krow("ICMP",                 "ICMP / ICMPv6 echo, errors");
        html += krow("DNS",                  "DNS (port 53) &mdash; shows DNS info popup");
        html += krow("DHCP",                 "DHCP / BOOTP (ports 67 / 68) &mdash; shows DHCP info popup");
        html += krow("TCP",                  "All TCP sessions");
        html += krow("UDP",                  "All UDP flows");
        html += krow("IGMP",                 "Multicast group management (v1 / v2 / v3)");
        html += krow("GRE",                  "GRE tunnel endpoints");
        html += krow("IPSEC  /  ESP  /  AH", "IPsec encrypted / authenticated traffic");
        html += krow("Routing",              "RIP, OSPF, BGP, EIGRP, IS-IS, PIM, VRRP, HSRP");
        html += krow("Infrastructure",       "All routing + bridge/switching + GRE + DHCP");
        html += krow("Unknown",              "Unclassified / generic IP pairs");
        html += "</table>";

        html += QString("<p style='color:%1; margin:6px 0 2px 0;'>"
                        "<b>Protocol info keywords</b> (show pairs with info popup):</p>").arg(head);
        html += "<table cellpadding='0' cellspacing='0'>";
        html += krow("TLS  /  SSL  /  HTTPS",  "TLS/SSL sessions (ports 443, 465, 993, 995, 8443)");
        html += krow("HTTP",                    "HTTP sessions (ports 80, 8080, 8000, 8888)");
        html += krow("SMB  /  CIFS",            "SMB/CIFS file sharing (ports 445, 139)");
        html += krow("Kerberos  /  KRB",        "Kerberos authentication (port 88)");
        html += krow("SMTP  /  email  /  mail", "SMTP mail sessions (ports 25, 465, 587)");
        html += krow("IMAP",                    "IMAP mail sessions (ports 143, 993)");
        html += krow("POP3  /  POP",            "POP3 mail sessions (ports 110, 995)");
        html += krow("SQL  /  MSSQL",           "Microsoft SQL Server (port 1433)");
        html += krow("MySQL",                   "MySQL / MariaDB (port 3306)");
        html += krow("PostgreSQL  /  PGSQL",    "PostgreSQL (port 5432)");
        html += krow("VoIP  /  SIP",            "VoIP / SIP signaling (ports 5060, 5061)");
        html += "</table>";

        html += QString("<p style='color:%1; margin:6px 0 2px 0;'><b>Port search:</b></p>").arg(head);
        html += "<table cellpadding='0' cellspacing='0'>";
        html += krow("TCP 443",   "TCP port 443 only");
        html += krow("UDP 53",    "UDP port 53 only");
        html += "</table>";

        html += QString("<p style='color:%1; margin:6px 0 2px 0;'><b>Address / CIDR:</b></p>").arg(head);
        html += "<table cellpadding='0' cellspacing='0'>";
        html += krow("192.168",      "Partial IPv4 match (src or dst)");
        html += krow("10.0.0.0/24", "CIDR range");
        html += krow("2001:db8::",  "Partial IPv6 match");
        html += "</table>";

    } else {
        /* ---- MAC mode ---- */
        html += QString("<h3 style='color:%1; margin:4px 0;'>Search Options &mdash; MAC Mode</h3>").arg(head);

        html += QString("<p style='color:%1; margin:6px 0 2px 0;'><b>Protocol keywords</b>"
                        " (press Enter):</p>").arg(head);
        html += "<table cellpadding='0' cellspacing='0'>";
        html += krow("ARP",                 "ARP / RARP broadcasts");
        html += krow("STP  RSTP  MSTP",     "Spanning Tree Protocol variants");
        html += krow("PVST  PVST+",         "Per-VLAN Spanning Tree");
        html += krow("LLDP",                "Link Layer Discovery Protocol (0x88CC)");
        html += krow("LACP",                "Link Aggregation Control Protocol (0x8809)");
        html += krow("CDP",                 "Cisco Discovery Protocol");
        html += krow("VTP",                 "VLAN Trunking Protocol");
        html += krow("Infrastructure",      "All bridge/switching + routing protocols (STP, LLDP, LACP, CDP, VTP, MPLS, OSPF, BGP &hellip;)");
        html += krow("LLC  /  802.2",       "IEEE 802.2 LLC-encapsulated frames");
        html += krow("EAPOL  /  802.1X",    "Port-based authentication &mdash; shows EAP info popup");
        html += krow("VLAN  /  802.1Q",     "IEEE 802.1Q tagged frames &mdash; shows VLAN info popup");
        html += krow("MACsec  /  802.1AE",  "MACsec encrypted frames (0x88E5) &mdash; shows MACsec info popup");
        html += krow("MPLS",                "MPLS labeled frames");
        html += krow("802.3  /  Ethernet",  "All Ethernet pairs");
        html += "</table>";

        html += QString("<p style='color:%1; margin:6px 0 2px 0;'><b>MAC address (partial):</b></p>").arg(head);
        html += "<table cellpadding='0' cellspacing='0'>";
        html += krow("aa:bb",    "Any MAC starting with aa:bb");
        html += krow("00:1a:2b", "Partial match on source or destination");
        html += "</table>";
    }

    html += QString("<br><div style='color:%1; font-size:10px;'>"
                    "<b>Wireshark display filter fallback:</b> If a search term returns no results, "
                    "PacketCircle will offer to apply it as a Wireshark display filter "
                    "(e.g. <span style='font-family:monospace;'>http.host contains \"github\"</span>, "
                    "<span style='font-family:monospace;'>ip.ttl &lt; 10</span>). "
                    "This reloads the PacketCircle view with only the matching packets."
                    "</div>").arg(dim);
    html += QString("<br><div style='color:%1; font-size:10px; font-style:italic;'>"
                    "Type <b>?</b> and press Enter to show this help.</div>").arg(dim);
    html += "</div>";

    QDialog *dlg = new QDialog(this);
    dlg->setWindowTitle("Search Help");
    dlg->setAttribute(Qt::WA_DeleteOnClose);
    dlg->setMinimumSize(500, 400);
    dlg->resize(540, 460);

    QVBoxLayout *layout = new QVBoxLayout(dlg);
    layout->setContentsMargins(10, 10, 10, 10);
    layout->setSpacing(8);

    QTextBrowser *tb = new QTextBrowser(dlg);
    tb->setReadOnly(true);
    tb->setOpenExternalLinks(false);
    if (dark)
        tb->setStyleSheet("QTextBrowser { background:#1e1e1e; color:#e0e0e0; border:1px solid #555; }");
    tb->setHtml(html);
    layout->addWidget(tb);

    QPushButton *closeBtn = new QPushButton("Close", dlg);
    closeBtn->setFixedWidth(80);
    connect(closeBtn, &QPushButton::clicked, dlg, &QDialog::accept);
    layout->addWidget(closeBtn, 0, Qt::AlignRight);

    dlg->setLayout(layout);
    dlg->exec();
}

/* ─── Search override mode helpers ─────────────────────────────────────────── */

/* Enter "search override" mode: bypass Top-N and show only the given pairs.
 * All three Top-N buttons are deselected. Mode stays active until the search
 * field is cleared or the user clicks one of the Top-N buttons.               */
void MainWindow::enterSearchOverrideMode(const QList<comm_pair_t*> &matches,
                                         const QString & /*query*/)
{
    /* Save current Top-N so we can restore it on exit */
    m_savedTopN = m_topN;

    /* Free any previous override list (list nodes only — pairs owned by m_analysisResult) */
    if (m_searchOverridePairs) {
        g_list_free(m_searchOverridePairs);
        m_searchOverridePairs = NULL;
    }
    /* Build GList from matches */
    for (comm_pair_t *p : matches)
        m_searchOverridePairs = g_list_append(m_searchOverridePairs, p);

    m_searchOverrideMode = true;

    /* Deselect all three Top-N buttons (exclusive group: must temporarily allow none) */
    QButtonGroup *grp = m_top10Btn ? m_top10Btn->group() : nullptr;
    if (grp) grp->setExclusive(false);
    if (m_top10Btn) m_top10Btn->setChecked(false);
    if (m_top25Btn) m_top25Btn->setChecked(false);
    if (m_top50Btn) m_top50Btn->setChecked(false);
    if (grp) grp->setExclusive(true);

    /* Rebuild views with the override pairs, then highlight them all */
    updateViews();
    updateLegend();   /* refresh category checkboxes to reflect the filtered pair set */

    /* Highlight every row that is now in the list */
    m_highlightedPairItems.clear();
    if (m_pairListWidget) {
        for (int i = 0; i < m_pairListWidget->count(); i++) {
            QListWidgetItem *item = m_pairListWidget->item(i);
            if (item) {
                item->setBackground(QBrush(m_darkTheme ? QColor(120, 100, 30)
                                                       : QColor(255, 248, 200)));
                m_highlightedPairItems.append(i);
            }
        }
    }
    if (m_pairListBlinkTimer && !m_highlightedPairItems.isEmpty())
        m_pairListBlinkTimer->start(500);
}

/* Restore Top-N mode: re-enable the saved Top-N button, clear tints, rebuild views. */
void MainWindow::exitSearchOverrideMode()
{
    if (!m_searchOverrideMode) return;

    m_searchOverrideMode = false;
    if (m_searchOverridePairs) {
        g_list_free(m_searchOverridePairs);
        m_searchOverridePairs = NULL;
    }

    /* Restore saved Top-N and re-check the correct button */
    m_topN = m_savedTopN;
    QButtonGroup *grp = m_top10Btn ? m_top10Btn->group() : nullptr;
    if (grp) grp->setExclusive(false);
    if (m_top10Btn) m_top10Btn->setChecked(m_savedTopN == 10);
    if (m_top25Btn) m_top25Btn->setChecked(m_savedTopN == 25);
    if (m_top50Btn) m_top50Btn->setChecked(m_savedTopN == 50);
    if (grp) grp->setExclusive(true);
}

/* ─────────────────────────────────────────────────────────────────────────── */

void MainWindow::applySearchFilter(const QString &query)
{
    QString trimmed = query.trimmed();
    QSet<QString> highlighted_labels;

    /* Clear old highlights and stop blink timer */
    m_highlightedPairItems.clear();
    if (m_pairListBlinkTimer->isActive()) {
        m_pairListBlinkTimer->stop();
    }
    m_pairListBlinkState = false;

    if (trimmed.isEmpty()) {
        /* If we were in override mode, exit it and rebuild the normal Top-N view */
        if (m_searchOverrideMode) {
            exitSearchOverrideMode();
            updateViews();
            updateLegend();   /* restore legend to full Top-N set */
        }
        if (m_circleWidget) m_circleWidget->setHighlightedLabels(highlighted_labels);
        if (m_graphWidget)  m_graphWidget->setHighlightedLabels(highlighted_labels);
        if (m_pairListWidget) {
            for (int i = 0; i < m_pairListWidget->count(); i++) {
                QListWidgetItem *list_item = m_pairListWidget->item(i);
                if (list_item) {
                    list_item->setBackground(QBrush());
                    list_item->setForeground(QBrush());
                    QFont f = list_item->font();
                    f.setBold(false);
                    list_item->setFont(f);
                }
            }
        }
        return;
    }

    /* "?" → show contextual search-help dialog and clear the field */
    if (trimmed == "?") {
        showSearchHelp();
        if (m_searchLineEdit) m_searchLineEdit->clear();
        return;
    }

    /* ── Mode-mismatch detection ──────────────────────────────────────────── *
     * Fires when the search term unambiguously belongs to the OTHER mode.     *
     * Three signal types are checked:                                         *
     *   0. ARP special case — valid in both modes, but suggest MAC because   *
     *      ARP is a Layer-2 protocol; MAC mode shows full Ethernet detail.   *
     *   1. Address pattern — MAC (hex pairs ≥3, colon/hyphen separated)      *
     *                        IP  (decimal octets ≥3, dot separated / CIDR)   *
     *   2. Protocol keyword — MAC-only: stp/rstp/mstp/pvst/lldp/lacp/…      *
     *                         IP-only : icmp/tcp/udp/dhcp/igmp/gre/ipsec/…  *
     * On "Yes": switch mode, re-analyse (synchronous), then run the search.  *
     * On "No" : fall through and run the search in the current mode.         */
    if (!m_wifiMode) {
        QString lower = trimmed.toLower();

        /* ── 0. ARP in IP mode → suggest MAC mode ── */
        if (!m_useMAC && (lower == "arp" || lower == "rarp")) {
            auto ans = QMessageBox::question(
                this,
                "Switch to MAC Mode?",
                QString("ARP is a Layer-2 protocol. MAC mode shows Ethernet-level "
                        "ARP pairs with full hardware address detail.<br><br>"
                        "Switch to <b>MAC mode</b> and search ARP there?"),
                QMessageBox::Yes | QMessageBox::No,
                QMessageBox::Yes);
            if (ans == QMessageBox::Yes) {
                if (m_macBtn) m_macBtn->setChecked(true);
                onMACToggled(true);   /* synchronous re-analysis */
                if (m_searchLineEdit) m_searchLineEdit->setText(trimmed);
                applySearchFilter(trimmed);
                return;
            }
            /* No → fall through and search ARP in IP mode */
        } else {
            /* ── 1 & 2. Generic address-pattern / keyword mismatch ── */
            static const QRegularExpression macAddrRx(
                "^[0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){2,5}$|"
                "^[0-9a-fA-F]{1,2}(?:-[0-9a-fA-F]{1,2}){2,5}$");
            static const QRegularExpression ipAddrRx(
                "^\\d{1,3}(?:\\.\\d{1,3}){2,3}(?:/\\d{1,2})?$");
            static const QStringList macOnlyKeywords = {
                "stp", "rstp", "mstp", "pvst", "pvst+",
                "lldp", "lacp", "cdp", "vtp",
                "llc", "802.2", "eapol", "802.1x",
                "vlan", "802.1q", "mpls",
                "802.3", "ethernet",
                "macsec", "802.1ae"
            };
            static const QStringList ipOnlyKeywords = {
                "icmp", "icmpv6", "tcp", "udp",
                "dhcp", "bootp", "igmp",
                "dns", "mdns",
                "gre", "ipsec", "esp", "ah",
                "routing", "unknown",
                /* Protocol-info keywords (map to known port ranges) */
                "tls", "ssl", "https",
                "http",
                "smb", "cifs",
                "ftp",
                "telnet",
                "kerberos", "krb", "krb5",
                "smtp", "email", "mail",
                "imap",
                "pop3", "pop",
                "sql", "mssql", "mysql", "postgresql", "pgsql", "postgres",
                "voip", "sip",
                "ssh", "sftp", "scp",
                "ldap", "ldaps",
                "snmp",
                "syslog",
                "nbns", "nbdgm", "nbss", "netbios"
            };
            static const QRegularExpression portSearchRx(
                "^(?:port|tcp|udp)\\s*\\d+$", QRegularExpression::CaseInsensitiveOption);

            bool looksLikeMAC = macAddrRx.match(trimmed).hasMatch()
                                || macOnlyKeywords.contains(lower);
            bool looksLikeIP  = ipAddrRx.match(trimmed).hasMatch()
                                || ipOnlyKeywords.contains(lower)
                                || portSearchRx.match(trimmed).hasMatch();

            if (!m_useMAC && looksLikeMAC) {
                auto ans = QMessageBox::question(
                    this,
                    "Switch to MAC Mode?",
                    QString("<b>%1</b> is a MAC-mode search term, but PacketCircle "
                            "is currently in <b>IP mode</b>.<br><br>"
                            "Switch to <b>MAC mode</b> and search there?")
                        .arg(trimmed.toHtmlEscaped()),
                    QMessageBox::Yes | QMessageBox::No,
                    QMessageBox::Yes);
                if (ans == QMessageBox::Yes) {
                    if (m_macBtn) m_macBtn->setChecked(true);
                    onMACToggled(true);
                    if (m_searchLineEdit) m_searchLineEdit->setText(trimmed);
                    applySearchFilter(trimmed);
                    return;
                }
            } else if (m_useMAC && looksLikeIP) {
                auto ans = QMessageBox::question(
                    this,
                    "Switch to IP Mode?",
                    QString("<b>%1</b> is an IP-mode search term, but PacketCircle "
                            "is currently in <b>MAC mode</b>.<br><br>"
                            "Switch to <b>IP mode</b> and search there?")
                        .arg(trimmed.toHtmlEscaped()),
                    QMessageBox::Yes | QMessageBox::No,
                    QMessageBox::Yes);
                if (ans == QMessageBox::Yes) {
                    if (m_ipBtn) m_ipBtn->setChecked(true);
                    onIPToggled(true);
                    if (m_searchLineEdit) m_searchLineEdit->setText(trimmed);
                    applySearchFilter(trimmed);
                    return;
                }
            }
        }
    }

    /* --- Wi-Fi keyword searches: signal quality + AP highlight --- */
    bool is_signal_search = false;
    bool is_ap_search = false;
    int signal_rssi_min = 0, signal_rssi_max = 0;  /* inclusive range for average RSSI */
    if (m_wifiMode) {
        QString lower = trimmed.toLower();
        if (lower == "excellent") {
            is_signal_search = true; signal_rssi_min = -55; signal_rssi_max = 0;
        } else if (lower == "good") {
            is_signal_search = true; signal_rssi_min = -65; signal_rssi_max = -56;
        } else if (lower == "fair") {
            is_signal_search = true; signal_rssi_min = -75; signal_rssi_max = -66;
        } else if (lower == "poor") {
            is_signal_search = true; signal_rssi_min = -200; signal_rssi_max = -76;
        } else if (lower == "ap" || lower == "accesspoint" || lower == "accesspoints" || lower == "bssid") {
            is_ap_search = true;
        }
    }

    /* --- Detect port search: "TCP <port>" or "UDP <port>" --- */
    bool is_port_search = false;
    bool port_search_tcp = false;
    bool port_search_udp = false;
    guint16 port_search_num = 0;

    if (!is_signal_search && !is_ap_search) {
        /* Accept e.g. "TCP 443", "udp 53", "tcp23", "UDP53" */
        QRegularExpression portRx("^(tcp|udp)\\s*(\\d+)$", QRegularExpression::CaseInsensitiveOption);
        QRegularExpressionMatch portMatch = portRx.match(trimmed);
        if (portMatch.hasMatch()) {
            QString proto = portMatch.captured(1).toUpper();
            bool ok = false;
            int portVal = portMatch.captured(2).toInt(&ok);
            if (ok && portVal > 0 && portVal <= 65535) {
                is_port_search = true;
                port_search_num = (guint16)portVal;
                port_search_tcp = (proto == "TCP");
                port_search_udp = (proto == "UDP");
            }
        }

        /* Also accept "port 443", "port23" — matches both TCP and UDP */
        if (!is_port_search) {
            QRegularExpression portNumRx("^port\\s*(\\d+)$", QRegularExpression::CaseInsensitiveOption);
            QRegularExpressionMatch portNumMatch = portNumRx.match(trimmed);
            if (portNumMatch.hasMatch()) {
                bool ok = false;
                int portVal = portNumMatch.captured(1).toInt(&ok);
                if (ok && portVal > 0 && portVal <= 65535) {
                    is_port_search = true;
                    port_search_num = (guint16)portVal;
                    port_search_tcp = true;   /* port N &mdash; match both TCP and UDP */
                    port_search_udp = true;
                }
            }
        }
    }

    /* --- Detect protocol category search (IP + MAC mode, not Wi-Fi) -------------------- *
     * IP mode:  ARP, ICMP, TCP, UDP, DHCP, IGMP, GRE, IPSEC/ESP/AH, Routing,           *
     *           Infrastructure, Unknown                                                   *
     * MAC mode: ARP, STP/RSTP/MSTP/PVST, LLDP, LACP, CDP, VTP, LLC/802.2, EAPOL/802.1X,*
     *           VLAN/802.1Q, MPLS, 802.3/Ethernet (matches ALL MAC pairs)                *
     * category_tcp / category_udp: also match pairs with has_tcp / has_udp flag.         *
     * category_match_all_mac: "802.3"/"Ethernet" — match every MAC pair regardless.      */
    bool is_category_search     = false;
    bool category_tcp           = false;
    bool category_udp           = false;
    bool category_match_all_mac = false;
    QStringList category_protocols;

    if (!is_port_search && !is_signal_search && !is_ap_search && !m_wifiMode) {
        QString lower = trimmed.toLower();
        if (!m_useMAC) {
            /* ---- IP mode ---- */
            if      (lower == "arp"  || lower == "rarp")
                category_protocols << "ARP" << "RARP";
            else if (lower == "icmp" || lower == "icmpv6")
                category_protocols << "ICMP" << "ICMPv6";
            else if (lower == "tcp")  { category_protocols << "TCP"; category_tcp = true; }
            else if (lower == "udp")  { category_protocols << "UDP"; category_udp = true; }
            else if (lower == "dhcp" || lower == "bootp")
                category_protocols << "DHCP" << "BOOTP";
            else if (lower == "dns")
                category_protocols << "DNS";
            else if (lower == "mdns")
                category_protocols << "MDNS";
            else if (lower == "igmp")
                category_protocols << "IGMP" << "IGMPv2" << "IGMPv3";
            else if (lower == "gre")
                category_protocols << "GRE";
            else if (lower == "ipsec" || lower == "esp" || lower == "ah")
                category_protocols << "IPSEC" << "ESP" << "AH" << "IKE";
            else if (lower == "routing")
                category_protocols << "OSPF" << "BGP" << "RIP" << "RIPv2" << "EIGRP"
                                   << "ISIS" << "IS-IS" << "PIM" << "VRRP" << "HSRP";
            else if (lower == "infrastructure")
                category_protocols << "OSPF" << "BGP" << "RIP" << "RIPv2" << "EIGRP"
                                   << "ISIS" << "IS-IS" << "IGMP" << "IGMPv2" << "IGMPv3"
                                   << "PIM" << "VRRP" << "HSRP" << "SCTP" << "DCCP"
                                   << "GRE" << "IPSEC" << "ESP" << "AH" << "IKE"
                                   << "DHCP" << "BOOTP"
                                   /* Bridge / switching infrastructure */
                                   << "STP" << "RSTP" << "MSTP" << "PVST" << "PVST+"
                                   << "LLDP" << "LACP" << "CDP" << "VTP" << "MPLS";
            else if (lower == "unknown")
                category_protocols << "Unknown" << "IP" << "IPv4" << "IPv6" << "Ethernet";
            if (!category_protocols.isEmpty())
                is_category_search = true;
        } else {
            /* ---- MAC mode ---- */
            if      (lower == "arp"  || lower == "rarp")
                category_protocols << "ARP" << "RARP";
            else if (lower == "stp"  || lower == "rstp" || lower == "mstp"
                                     || lower == "pvst" || lower == "pvst+")
                category_protocols << "STP" << "RSTP" << "MSTP" << "PVST" << "PVST+";
            else if (lower == "lldp")
                category_protocols << "LLDP";
            else if (lower == "lacp")
                category_protocols << "LACP";
            else if (lower == "cdp")
                category_protocols << "CDP";
            else if (lower == "vtp")
                category_protocols << "VTP";
            else if (lower == "llc" || lower == "802.2")
                category_protocols << "LLC";
            else if (lower == "eapol" || lower == "802.1x")
                category_protocols << "EAPOL" << "EAP";
            else if (lower == "vlan" || lower == "802.1q")
                category_protocols << "VLAN" << "802.1Q";
            else if (lower == "mpls")
                category_protocols << "MPLS";
            else if (lower == "infrastructure")
                /* Bridge/switching + routing protocols visible in MAC-mode captures */
                category_protocols << "STP" << "RSTP" << "MSTP" << "PVST" << "PVST+"
                                   << "LLDP" << "LACP" << "CDP" << "VTP" << "MPLS"
                                   << "OSPF" << "BGP" << "RIP" << "RIPv2" << "EIGRP"
                                   << "ISIS" << "IS-IS" << "PIM" << "VRRP" << "HSRP";
            else if (lower == "macsec" || lower == "802.1ae")
                category_protocols << "MACsec";
            else if (lower == "802.3" || lower == "ethernet")
                category_match_all_mac = true;  /* match ALL MAC-mode pairs */
            if (!category_protocols.isEmpty() || category_match_all_mac)
                is_category_search = true;
        }
    }

    /* arp/rarp also valid in Wi-Fi mode (ARP still runs over 802.11) */
    if (!is_category_search && !is_port_search && !is_signal_search && !is_ap_search) {
        QString lower = trimmed.toLower();
        if (lower == "arp" || lower == "rarp") {
            category_protocols << "ARP" << "RARP";
            is_category_search = true;
        }
    }

    /* ── Protocol-info port search ───────────────────────────────────────────── *
     * Maps friendly keywords to the port(s) used by protocols that have a       *
     * protocol information popup in PacketCircle.  Matching is done against the  *
     * per-pair dst_ports hash table (same mechanism as the existing port search). *
     * Only active in IP mode (non-MAC, non-Wi-Fi).                              */
    bool is_proto_info_search = false;
    QList<guint16> proto_info_ports;
    bool proto_info_tcp_only = false;  /* true &rarr; require TCP; false &rarr; accept TCP or UDP */

    if (!is_port_search && !is_signal_search && !is_ap_search
            && !is_category_search && !m_useMAC && !m_wifiMode) {
        QString lower = trimmed.toLower();
        if (lower == "tls" || lower == "ssl" || lower == "https") {
            proto_info_ports << 443 << 465 << 993 << 995 << 8443;
            proto_info_tcp_only = true;
            is_proto_info_search = true;
        } else if (lower == "http") {
            proto_info_ports << 80 << 8080 << 8000 << 8888;
            proto_info_tcp_only = true;
            is_proto_info_search = true;
        } else if (lower == "smb" || lower == "cifs") {
            proto_info_ports << 445 << 135;
            proto_info_tcp_only = true;
            is_proto_info_search = true;
        } else if (lower == "kerberos" || lower == "krb" || lower == "krb5") {
            proto_info_ports << 88;   /* TCP + UDP both valid */
            is_proto_info_search = true;
        } else if (lower == "smtp" || lower == "email" || lower == "mail") {
            proto_info_ports << 25 << 465 << 587;
            proto_info_tcp_only = true;
            is_proto_info_search = true;
        } else if (lower == "imap") {
            proto_info_ports << 143 << 993;
            proto_info_tcp_only = true;
            is_proto_info_search = true;
        } else if (lower == "pop3" || lower == "pop") {
            proto_info_ports << 110 << 995;
            proto_info_tcp_only = true;
            is_proto_info_search = true;
        } else if (lower == "sql" || lower == "mssql") {
            proto_info_ports << 1433;
            proto_info_tcp_only = true;
            is_proto_info_search = true;
        } else if (lower == "mysql") {
            proto_info_ports << 3306;
            proto_info_tcp_only = true;
            is_proto_info_search = true;
        } else if (lower == "postgresql" || lower == "pgsql" || lower == "postgres") {
            proto_info_ports << 5432;
            proto_info_tcp_only = true;
            is_proto_info_search = true;
        } else if (lower == "voip" || lower == "sip") {
            proto_info_ports << 5060 << 5061;   /* TCP + UDP */
            is_proto_info_search = true;
        } else if (lower == "ssh" || lower == "sftp" || lower == "scp") {
            proto_info_ports << 22;
            proto_info_tcp_only = true;
            is_proto_info_search = true;
        } else if (lower == "ftp") {
            proto_info_ports << 21 << 20;
            proto_info_tcp_only = true;
            is_proto_info_search = true;
        } else if (lower == "telnet") {
            proto_info_ports << 23;
            proto_info_tcp_only = true;
            is_proto_info_search = true;
        } else if (lower == "ldap" || lower == "ldaps") {
            proto_info_ports << 389 << 636 << 3268 << 3269;
            proto_info_tcp_only = true;
            is_proto_info_search = true;
        } else if (lower == "snmp") {
            proto_info_ports << 161 << 162;   /* TCP + UDP */
            is_proto_info_search = true;
        } else if (lower == "syslog") {
            proto_info_ports << 514 << 6514;  /* UDP 514, TLS 6514 */
            is_proto_info_search = true;
        } else if (lower == "nbns" || lower == "netbios-ns") {
            proto_info_ports << 137;          /* UDP */
            proto_info_tcp_only = false;
            is_proto_info_search = true;
        } else if (lower == "nbdgm" || lower == "netbios" || lower == "netbios-dgm"
                   || lower == "netbios-datagram") {
            proto_info_ports << 138;          /* UDP */
            proto_info_tcp_only = false;
            is_proto_info_search = true;
        } else if (lower == "nbss" || lower == "netbios-ssn" || lower == "netbios-session") {
            proto_info_ports << 139;          /* TCP */
            proto_info_tcp_only = true;
            is_proto_info_search = true;
        }
    }

    bool is_cidr = !is_port_search && !is_signal_search && !is_ap_search
                && !is_category_search && !is_proto_info_search
                && trimmed.contains('/') && parse_cidr(trimmed, nullptr, nullptr);

    /* ---- Validate query: reject unrecognised strings before running the pair loop ---- *
     * Recognised: category/protocol keyword, TCP/UDP port, CIDR, Wi-Fi signal/ap,       *
     * or any string containing only address characters (digits, dots, colons, hex).      *
     * Purely alphabetic strings that don't match a known keyword are reported invalid.   */
    bool is_valid_search = (is_signal_search || is_ap_search || is_port_search
                         || is_category_search || is_cidr || is_proto_info_search);
    if (!is_valid_search) {
        /* Accept partial IP / MAC / IPv6 addresses — digits, dots, colons, hex chars */
        static const QRegularExpression addrRx("^[0-9a-fA-F.:]+$");
        is_valid_search = addrRx.match(trimmed).hasMatch() && trimmed.length() >= 2;
    }
    if (!is_valid_search) {
        /* Not a recognised PacketCircle search term — offer Wireshark display filter delegation */
        auto ans = QMessageBox::question(this,
            "Try as Wireshark Display Filter?",
            QString("<b>%1</b> is not a recognised PacketCircle search term.<br><br>"
                    "Would you like to apply it as a <b>Wireshark display filter</b> and "
                    "reload the PacketCircle view?<br><br>"
                    "<small>\u26a0 Note: Applying a display filter requires Wireshark to "
                    "re-process the capture. This may take additional time on large captures.</small>")
                .arg(trimmed.toHtmlEscaped()),
            QMessageBox::Yes | QMessageBox::No,
            QMessageBox::Yes);
        if (ans == QMessageBox::Yes) {
            applyAsDisplayFilter(trimmed);
        } else {
            showSearchHelp();
            if (m_searchLineEdit) m_searchLineEdit->clear();
        }
        return;
    }

    if (m_pairListWidget) {
        for (int i = 0; i < m_pairListWidget->count(); i++) {
            QListWidgetItem *list_item = m_pairListWidget->item(i);
            if (!list_item)
                continue;
            comm_pair_t *pair = (comm_pair_t *)list_item->data(Qt::UserRole).value<void*>();
            if (!pair || !pair->src_addr || !pair->dst_addr) {
                list_item->setBackground(QBrush());
                continue;
            }

            bool match = false;

            if (is_ap_search) {
                /* AP search: highlight every BSSID (dst_addr in station→BSSID pairs) */
                if (pair->is_wifi && pair->wifi_bssid) {
                    match = true;
                    /* Only highlight the BSSID node, not the station */
                    highlighted_labels.insert(QString::fromUtf8(pair->wifi_bssid));
                }
            } else if (is_signal_search) {
                /* Signal quality search: match Wi-Fi pairs by average RSSI bin */
                if (pair->is_wifi && pair->rssi_count > 0) {
                    int avg = (int)(pair->rssi_sum / (gint32)pair->rssi_count);
                    if (signal_rssi_max == 0) {
                        /* "excellent": >= -55 (open-ended upper bound) */
                        match = (avg >= signal_rssi_min);
                    } else {
                        match = (avg >= signal_rssi_min && avg <= signal_rssi_max);
                    }
                }
                if (match) {
                    highlighted_labels.insert(QString::fromUtf8(pair->src_addr));
                    highlighted_labels.insert(QString::fromUtf8(pair->dst_addr));
                }
            } else if (is_category_search) {
                /* Category / protocol search */
                if (category_match_all_mac) {
                    /* "802.3" / "Ethernet" — match every MAC-mode pair */
                    match = pair->is_mac;
                } else if (pair->top_protocol) {
                    QString proto = QString::fromUtf8(pair->top_protocol);
                    if (category_protocols.contains(proto, Qt::CaseInsensitive))
                        match = true;
                }
                /* For TCP/UDP categories, also check has_tcp / has_udp flags */
                if (category_tcp && pair->has_tcp) match = true;
                if (category_udp && pair->has_udp) match = true;

                if (match) {
                    highlighted_labels.insert(QString::fromUtf8(pair->src_addr));
                    highlighted_labels.insert(QString::fromUtf8(pair->dst_addr));
                }
            } else if (is_port_search) {
                /* Port search: check this pair's dst_ports (and reverse pair's) */
                auto checkPorts = [&](comm_pair_t *p) -> bool {
                    if (!p || !p->dst_ports) return false;
                    gpointer port_key = GUINT_TO_POINTER((guint)port_search_num);
                    port_stats_t *ps = (port_stats_t *)g_hash_table_lookup(p->dst_ports, port_key);
                    if (!ps) return false;
                    if (port_search_tcp && ps->is_tcp) return true;
                    if (port_search_udp && ps->is_udp) return true;
                    return false;
                };

                match = checkPorts(pair);

                /* Also check the reverse pair (B→A for the same port) */
                if (!match && m_analysisResult && m_analysisResult->pairs) {
                    for (GList *gl = m_analysisResult->pairs; gl; gl = gl->next) {
                        comm_pair_t *rp = (comm_pair_t *)gl->data;
                        if (rp && rp != pair &&
                            g_strcmp0(rp->src_addr, pair->dst_addr) == 0 &&
                            g_strcmp0(rp->dst_addr, pair->src_addr) == 0) {
                            match = checkPorts(rp);
                            break;
                        }
                    }
                }

                if (match) {
                    QString src = QString::fromUtf8(pair->src_addr);
                    QString dst = QString::fromUtf8(pair->dst_addr);
                    highlighted_labels.insert(src);
                    highlighted_labels.insert(dst);
                }
            } else if (is_proto_info_search) {
                /* Protocol-info keyword search: check against known port list */
                auto checkProtoPorts = [&](comm_pair_t *p) -> bool {
                    if (!p || !p->dst_ports) return false;
                    for (guint16 chkPort : proto_info_ports) {
                        gpointer port_key = GUINT_TO_POINTER((guint)chkPort);
                        port_stats_t *ps = (port_stats_t *)g_hash_table_lookup(
                                              p->dst_ports, port_key);
                        if (!ps) continue;
                        if (proto_info_tcp_only) {
                            if (ps->is_tcp) return true;
                        } else {
                            if (ps->is_tcp || ps->is_udp) return true;
                        }
                    }
                    return false;
                };

                match = checkProtoPorts(pair);

                /* Also check the reverse pair so bidirectional flows are found */
                if (!match && m_analysisResult && m_analysisResult->pairs) {
                    for (GList *gl = m_analysisResult->pairs; gl; gl = gl->next) {
                        comm_pair_t *rp = (comm_pair_t *)gl->data;
                        if (rp && rp != pair &&
                            g_strcmp0(rp->src_addr, pair->dst_addr) == 0 &&
                            g_strcmp0(rp->dst_addr, pair->src_addr) == 0) {
                            match = checkProtoPorts(rp);
                            break;
                        }
                    }
                }

                if (match) {
                    highlighted_labels.insert(QString::fromUtf8(pair->src_addr));
                    highlighted_labels.insert(QString::fromUtf8(pair->dst_addr));
                }
            } else {
                /* Address search (IP, MAC, CIDR) + Wi-Fi SSID/BSSID */
                QString src = QString::fromUtf8(pair->src_addr);
                QString dst = QString::fromUtf8(pair->dst_addr);

                bool src_match = is_cidr ? ipv4_in_cidr(src, trimmed) : src.contains(trimmed, Qt::CaseInsensitive);
                bool dst_match = is_cidr ? ipv4_in_cidr(dst, trimmed) : dst.contains(trimmed, Qt::CaseInsensitive);

                /* In Wi-Fi mode, also match SSID and BSSID */
                bool wifi_match = false;
                if (m_wifiMode && pair->is_wifi) {
                    if (pair->wifi_ssid && QString::fromUtf8(pair->wifi_ssid).contains(trimmed, Qt::CaseInsensitive))
                        wifi_match = true;
                    if (pair->wifi_bssid && QString::fromUtf8(pair->wifi_bssid).contains(trimmed, Qt::CaseInsensitive))
                        wifi_match = true;
                }

                match = src_match || dst_match || wifi_match;

                if (match) {
                    if (src_match || wifi_match) highlighted_labels.insert(src);
                    if (dst_match || wifi_match) highlighted_labels.insert(dst);
                }
            }

            if (match) {
                list_item->setBackground(QBrush(m_darkTheme ? QColor(120, 100, 30) : QColor(255, 248, 200)));
                m_highlightedPairItems.append(i);
            } else {
                list_item->setBackground(QBrush());
            }
        }
    }

    /* Start blink timer if we have matches */
    if (!m_highlightedPairItems.isEmpty()) {
        m_pairListBlinkTimer->start(500);
    } else {

        /* ── Full-buffer fallback ──────────────────────────────────────────────
         * Nothing matched in the current Top-N view.  Before telling the user
         * "no results", check every pair in the full capture buffer.  This
         * catches, for example, an ARP pair that exists in the trace but ranks
         * below the Top-10/25/50 cutoff by byte count.
         * Only done for non-Wi-Fi, non-signal searches and when not already in
         * override mode (avoids an infinite prompt loop).                      */
        bool offeredOverride = false;
        if (!m_wifiMode && !is_signal_search && !is_ap_search
                && !m_searchOverrideMode
                && m_analysisResult && m_analysisResult->pairs) {

            /* Scan all pairs in the full buffer using the same match criteria */
            QList<comm_pair_t*> fullMatches;
            QSet<QString> seenKeys;   /* deduplicate bidirectional pairs */

            for (GList *gl = m_analysisResult->pairs; gl; gl = gl->next) {
                comm_pair_t *pair = (comm_pair_t *)gl->data;
                if (!pair || !pair->src_addr || !pair->dst_addr) continue;

                bool match = false;

                if (is_category_search) {
                    if (category_match_all_mac) {
                        match = pair->is_mac;
                    } else if (pair->top_protocol) {
                        QString proto = QString::fromUtf8(pair->top_protocol);
                        if (category_protocols.contains(proto, Qt::CaseInsensitive))
                            match = true;
                    }
                    if (category_tcp && pair->has_tcp) match = true;
                    if (category_udp && pair->has_udp) match = true;

                } else if (is_port_search) {
                    auto checkPortsFull = [&](comm_pair_t *p) -> bool {
                        if (!p || !p->dst_ports) return false;
                        gpointer port_key = GUINT_TO_POINTER((guint)port_search_num);
                        port_stats_t *ps = (port_stats_t *)g_hash_table_lookup(
                                              p->dst_ports, port_key);
                        if (!ps) return false;
                        if (port_search_tcp && ps->is_tcp) return true;
                        if (port_search_udp && ps->is_udp) return true;
                        return false;
                    };
                    match = checkPortsFull(pair);

                } else if (is_proto_info_search) {
                    auto checkProtoPortsFull = [&](comm_pair_t *p) -> bool {
                        if (!p || !p->dst_ports) return false;
                        for (guint16 chkPort : proto_info_ports) {
                            gpointer port_key = GUINT_TO_POINTER((guint)chkPort);
                            port_stats_t *ps = (port_stats_t *)g_hash_table_lookup(
                                                  p->dst_ports, port_key);
                            if (!ps) continue;
                            if (proto_info_tcp_only) {
                                if (ps->is_tcp) return true;
                            } else {
                                if (ps->is_tcp || ps->is_udp) return true;
                            }
                        }
                        return false;
                    };
                    match = checkProtoPortsFull(pair);

                } else {
                    /* Address / CIDR search */
                    QString src = QString::fromUtf8(pair->src_addr);
                    QString dst = QString::fromUtf8(pair->dst_addr);
                    bool src_m = is_cidr ? ipv4_in_cidr(src, trimmed)
                                        : src.contains(trimmed, Qt::CaseInsensitive);
                    bool dst_m = is_cidr ? ipv4_in_cidr(dst, trimmed)
                                        : dst.contains(trimmed, Qt::CaseInsensitive);
                    match = src_m || dst_m;
                }

                if (match) {
                    /* Deduplicate: use a canonical key (sorted addr pair) */
                    QString a1 = QString::fromUtf8(pair->src_addr);
                    QString a2 = QString::fromUtf8(pair->dst_addr);
                    QString key = (a1 < a2) ? a1 + "|" + a2 : a2 + "|" + a1;
                    if (!seenKeys.contains(key)) {
                        seenKeys.insert(key);
                        fullMatches.append(pair);
                    }
                }
            }

            if (!fullMatches.isEmpty()) {
                offeredOverride = true;
                int count = (int)fullMatches.size();

                if (count > 25) {
                    /* Too many to display — tell user to refine */
                    QMessageBox::warning(this,
                        QString("Not in Top-%1 &mdash; Too Many Results").arg(m_topN),
                        QString("<b>%1</b> was not found in the current "
                                "<b>Top-%2</b> view.<br><br>"
                                "Found <b>%3 pairs</b> in the full capture buffer, "
                                "which exceeds the 25-pair display limit.<br><br>"
                                "Please refine your search to narrow down the results.")
                            .arg(trimmed.toHtmlEscaped())
                            .arg(m_topN)
                            .arg(count));
                } else {
                    /* Ask the user whether they want to see the override results */
                    QMessageBox mb(this);
                    mb.setWindowTitle(QString("Not in Current Top-%1 View").arg(m_topN));
                    mb.setIcon(QMessageBox::Question);
                    mb.setText(
                        QString("<b>%1</b> was not found in the current "
                                "<b>Top-%2</b> view.<br><br>"
                                "However, <b>%3 matching pair%4</b> %5 found "
                                "in the full capture buffer.<br><br>"
                                "If you continue:<br>"
                                "&bull; The Top-%2 buttons will be deselected<br>"
                                "&bull; The %3 matching pair%4 will be shown "
                                "in the pair list and circle view<br>"
                                "&bull; This custom view stays active until you "
                                "clear the search field or pick a Top-N button")
                            .arg(trimmed.toHtmlEscaped())
                            .arg(m_topN)
                            .arg(count)
                            .arg(count == 1 ? "" : "s")
                            .arg(count == 1 ? "was" : "were"));
                    mb.setStandardButtons(QMessageBox::Yes | QMessageBox::Cancel);
                    mb.setDefaultButton(QMessageBox::Yes);
                    mb.button(QMessageBox::Yes)->setText("Show Results");
                    mb.button(QMessageBox::Cancel)->setText("Cancel");

                    /* Force the dialog wide enough so each bullet fits on one line */
                    QGridLayout *mbLayout = qobject_cast<QGridLayout *>(mb.layout());
                    if (mbLayout)
                        mbLayout->addItem(
                            new QSpacerItem(700, 0, QSizePolicy::Minimum, QSizePolicy::Expanding),
                            mbLayout->rowCount(), 0, 1, mbLayout->columnCount());

                    if (mb.exec() == QMessageBox::Yes) {
                        enterSearchOverrideMode(fullMatches, trimmed);
                        /* Circle highlight is handled inside enterSearchOverrideMode */
                        return;
                    }
                }
            }
        }

        /* No results anywhere in the capture buffer.
         * In non-Wi-Fi mode: offer to delegate the query to Wireshark as a
         * display filter.  In Wi-Fi signal/AP mode: fall back to a plain message. */
        if (!offeredOverride) {
            if (!m_wifiMode) {
                auto ans = QMessageBox::question(this,
                    "Try as Wireshark Display Filter?",
                    QString("No pairs matching <b>%1</b> found in the current capture.<br><br>"
                            "Would you like to apply it as a <b>Wireshark display filter</b> and "
                            "reload the PacketCircle view?<br><br>"
                            "<small>\u26a0 Note: Applying a display filter requires Wireshark to "
                            "re-process the capture. This may take additional time on large captures.</small>")
                        .arg(trimmed.toHtmlEscaped()),
                    QMessageBox::Yes | QMessageBox::No,
                    QMessageBox::No);
                if (ans == QMessageBox::Yes) {
                    applyAsDisplayFilter(trimmed);
                    return;
                }
            } else if (is_signal_search || is_ap_search) {
                QMessageBox::information(this, "No Results",
                    QString("No pairs matching <b>%1</b> found in the current capture.<br><br>"
                            "Type <b>?</b> and press Enter for search options.")
                        .arg(trimmed.toHtmlEscaped()));
            }
        }
    }

    if (m_circleWidget) m_circleWidget->setHighlightedLabels(highlighted_labels);
    if (m_graphWidget)  m_graphWidget->setHighlightedLabels(highlighted_labels);
}

/* ─────────────────────────────────────────────────────────────────────────── *
 * applyAsDisplayFilter()                                                       *
 *                                                                               *
 * Delegates the search query to Wireshark as a display filter, then schedules  *
 * a PacketCircle reload so the view reflects only the matching packets.         *
 *                                                                               *
 * Flow:                                                                         *
 *   1. Apply the filter string to Wireshark's filter bar via plugin_if.         *
 *   2. Clear the search field (the display filter takes over).                  *
 *   3. After a short delay (giving Wireshark time to process the filter),       *
 *      re-run packet_analyzer_analyze() on the now-filtered capture file.       *
 *   4. If the analysis returns pairs → update the PacketCircle view normally.   *
 *   5. If it returns 0 pairs → show ":-( no packets found in the buffer".       *
 * ─────────────────────────────────────────────────────────────────────────── */
void MainWindow::applyAsDisplayFilter(const QString &filter)
{
    QByteArray filterBytes = filter.toUtf8();
    plugin_if_apply_filter(filterBytes.constData(), true);

    /* Clear the search bar — from here the Wireshark filter bar drives the view */
    if (m_searchLineEdit) m_searchLineEdit->clear();

    /* Give Wireshark a moment to process the filter before we re-analyse.
     * plugin_if_apply_filter posts to Wireshark's event queue on most
     * platforms; 400 ms is enough for the filter to be applied before
     * packet_analyzer_analyze() re-taps the (now filtered) capture.        */
    QTimer::singleShot(400, this, [this]() {
        capture_file *cf = (capture_file *)plugin_if_get_capture_file(
                               extract_capture_file, NULL);
        if (!cf) {
            QMessageBox::information(this, "Display Filter Applied",
                ":-( no packets found in the buffer");
            return;
        }

        analysis_result_t *result = packet_analyzer_analyze(cf, m_useMAC);

        if (!result || !result->pairs || g_list_length(result->pairs) == 0) {
            if (result) packet_analyzer_free_result(result);
            QMessageBox::information(this, "Display Filter Applied",
                ":-( no packets found in the buffer");
            return;
        }

        /* Pairs found — update the PacketCircle view */
        updateAnalysis(result);
    });
}

void MainWindow::onPairSelectionChanged(QList<comm_pair_t*> selected)
{
    m_selectedPairs = selected;
    updateViews();
}

void MainWindow::onNodeVisibilityToggle(QList<comm_pair_t*> pairs, bool enable)
{
    if (!m_pairListWidget || pairs.isEmpty())
        return;

    QSet<comm_pair_t*> pair_set(pairs.begin(), pairs.end());

    disconnect(m_pairListWidget, &QListWidget::itemChanged, this, &MainWindow::onPairListItemChanged);
    for (int i = 0; i < m_pairListWidget->count(); i++) {
        QListWidgetItem *list_item = m_pairListWidget->item(i);
        if (!list_item)
            continue;

        comm_pair_t *pair = (comm_pair_t *)list_item->data(Qt::UserRole).value<void*>();
        if (!pair)
            continue;

        if (pair_set.contains(pair)) {
            list_item->setCheckState(enable ? Qt::Checked : Qt::Unchecked);
        }
    }
    connect(m_pairListWidget, &QListWidget::itemChanged, this, &MainWindow::onPairListItemChanged);

    syncTableCheckboxesFromPairList();
    updateVisiblePairsFromWidgets();
}

void MainWindow::updateVisiblePairsFromWidgets()
{
    QSet<comm_pair_t*> visible_pairs;

    for (int i = 0; i < m_pairListWidget->count(); i++) {
        QListWidgetItem *list_item = m_pairListWidget->item(i);
        if (!list_item || list_item->checkState() != Qt::Checked)
            continue;

        /* Primary pair always made visible when row is checked */
        comm_pair_t *primary = (comm_pair_t*)list_item->data(Qt::UserRole).value<void*>();
        if (primary)
            visible_pairs.insert(primary);

        /* Secondary pair (reverse direction) also made visible so the circle
         * can render the line in both directions regardless of arrow state */
        comm_pair_t *secondary = (comm_pair_t*)list_item->data(Qt::UserRole + 1).value<void*>();
        if (secondary)
            visible_pairs.insert(secondary);
    }

    /* Update circle and graph widgets with visible pairs */
    if (m_circleWidget) m_circleWidget->setVisiblePairs(visible_pairs);
    if (m_graphWidget)  m_graphWidget->setVisiblePairs(visible_pairs);
}

void MainWindow::onPairListItemChanged(QListWidgetItem *item)
{
    if (!item)
        return;

    /* With one row per bidirectional group there is no separate linked item.
     * Just sync table checkboxes and update visible pairs. */
    syncTableCheckboxesFromPairList();
    updateVisiblePairsFromWidgets();
}

void MainWindow::onTableCheckboxToggled(comm_pair_t *pair, bool checked)
{
    if (!pair || !m_pairListWidget)
        return;
    
    /* Prevent recursive updates */
    static bool syncing = false;
    if (syncing)
        return;
    syncing = true;
    
    /* Find the matching pair list item (by primary or secondary pair pointer)
     * and update its check state.  With single rows per bidirectional group
     * there is no separate linked item to sync — one row covers both directions. */
    disconnect(m_pairListWidget, &QListWidget::itemChanged, this, &MainWindow::onPairListItemChanged);

    for (int i = 0; i < m_pairListWidget->count(); i++) {
        QListWidgetItem *list_item = m_pairListWidget->item(i);
        if (!list_item)
            continue;
        comm_pair_t *primary   = (comm_pair_t*)list_item->data(Qt::UserRole).value<void*>();
        comm_pair_t *secondary = (comm_pair_t*)list_item->data(Qt::UserRole + 1).value<void*>();
        if (primary == pair || secondary == pair) {
            list_item->setCheckState(checked ? Qt::Checked : Qt::Unchecked);
            break;
        }
    }

    connect(m_pairListWidget, &QListWidget::itemChanged, this, &MainWindow::onPairListItemChanged);
    updateVisiblePairsFromWidgets();
    
    syncing = false;
}

void MainWindow::syncTableCheckboxesFromPairList()
{
    /* Sync table checkboxes to match pair list state.
     * Each list item now holds primary (UserRole) and optional secondary (UserRole+1)
     * pair pointer, so we check both when looking up the row's checkbox. */
    for (auto it = m_tableCheckboxes.begin(); it != m_tableCheckboxes.end(); ++it) {
        QCheckBox *checkbox = it.key();
        comm_pair_t *pair = it.value();

        bool is_checked = false;
        for (int i = 0; i < m_pairListWidget->count(); i++) {
            QListWidgetItem *list_item = m_pairListWidget->item(i);
            if (!list_item) continue;
            comm_pair_t *primary   = (comm_pair_t*)list_item->data(Qt::UserRole).value<void*>();
            comm_pair_t *secondary = (comm_pair_t*)list_item->data(Qt::UserRole + 1).value<void*>();
            if (primary == pair || secondary == pair) {
                is_checked = (list_item->checkState() == Qt::Checked);
                break;
            }
        }

        checkbox->blockSignals(true);
        checkbox->setChecked(is_checked);
        checkbox->blockSignals(false);
    }
}

void MainWindow::onProtocolCheckboxToggled(const QString &protocol, bool checked)
{
    Q_UNUSED(protocol);
    Q_UNUSED(checked);
    
    /* Build set of enabled protocols (only from enabled checkboxes) */
    QSet<QString> enabled_protocols;
    for (auto it = m_protocolCheckboxes.begin(); it != m_protocolCheckboxes.end(); ++it) {
        QCheckBox *checkbox = it.value();
        /* Only consider enabled checkboxes that are checked */
        if (checkbox->isEnabled() && checkbox->isChecked()) {
            enabled_protocols.insert(it.key());
        }
    }
    
    /* If all enabled protocols are checked, use empty set to show all (more efficient) */
    guint enabled_count = 0;
    guint checked_count = 0;
    for (auto it = m_protocolCheckboxes.begin(); it != m_protocolCheckboxes.end(); ++it) {
        if (it.value()->isEnabled()) {
            enabled_count++;
            if (it.value()->isChecked()) {
                checked_count++;
            }
        }
    }
    if (enabled_count > 0 && checked_count == enabled_count) {
        enabled_protocols.clear();  /* Empty set = show all */
    }
    
    /* Update circle and graph widget filters */
    if (m_circleWidget) m_circleWidget->setProtocolFilter(enabled_protocols);
    if (m_graphWidget)  m_graphWidget->setProtocolFilter(enabled_protocols);
}

void MainWindow::onProtocolCategoryToggled(const QString &category, const QStringList &protocols, bool checked)
{
    Q_UNUSED(category);
    Q_UNUSED(protocols);
    Q_UNUSED(checked);
    
    /* Build set of enabled protocols from all categories */
    QSet<QString> enabled_protocols;
    for (auto it = m_protocolCheckboxes.begin(); it != m_protocolCheckboxes.end(); ++it) {
        QCheckBox *checkbox = it.value();
        /* Only consider enabled checkboxes that are checked */
        if (checkbox->isEnabled() && checkbox->isChecked()) {
            QString category_name = it.key();
            /* Map category to its protocols */
            if (category_name == "ARP") {
                enabled_protocols.insert("ARP");
                enabled_protocols.insert("RARP");
            } else if (category_name == "ICMP") {
                enabled_protocols.insert("ICMP");
                enabled_protocols.insert("ICMPv6");
            } else if (category_name == "TCP") {
                enabled_protocols.insert("TCP");
            } else if (category_name == "UDP") {
                enabled_protocols.insert("UDP");
            } else if (category_name == "Infrastructure") {
                enabled_protocols.insert("OSPF");
                enabled_protocols.insert("BGP");
                enabled_protocols.insert("RIP");
                enabled_protocols.insert("RIPv2");
                enabled_protocols.insert("EIGRP");
                enabled_protocols.insert("ISIS");
                enabled_protocols.insert("IS-IS");
                enabled_protocols.insert("IGMP");
                enabled_protocols.insert("IGMPv2");
                enabled_protocols.insert("IGMPv3");
                enabled_protocols.insert("PIM");
                enabled_protocols.insert("VRRP");
                enabled_protocols.insert("HSRP");
                enabled_protocols.insert("SCTP");
                enabled_protocols.insert("DCCP");
            } else if (category_name == "Unknown") {
                enabled_protocols.insert("Unknown");
                enabled_protocols.insert("IP");
                enabled_protocols.insert("IPv4");
                enabled_protocols.insert("IPv6");
                enabled_protocols.insert("Ethernet");
            }
        }
    }
    
    /* If all enabled categories are checked, use empty set to show all (more efficient) */
    guint enabled_count = 0;
    guint checked_count = 0;
    for (auto it = m_protocolCheckboxes.begin(); it != m_protocolCheckboxes.end(); ++it) {
        if (it.value()->isEnabled()) {
            enabled_count++;
            if (it.value()->isChecked()) {
                checked_count++;
            }
        }
    }
    if (enabled_count > 0 && checked_count == enabled_count) {
        enabled_protocols.clear();  /* Empty set = show all */
    }
    
    /* Update circle and graph widget filters */
    if (m_circleWidget) m_circleWidget->setProtocolFilter(enabled_protocols);
    if (m_graphWidget)  m_graphWidget->setProtocolFilter(enabled_protocols);

    /* Also sync pair list checkboxes to match the protocol filter.
     * This lets the user select/deselect pairs by protocol category
     * (e.g. uncheck TCP → unchecks all TCP pairs in the list).       */
    if (m_pairListWidget) {
        disconnect(m_pairListWidget, &QListWidget::itemChanged, this, &MainWindow::onPairListItemChanged);

        for (int i = 0; i < m_pairListWidget->count(); i++) {
            QListWidgetItem *item = m_pairListWidget->item(i);
            if (!item)
                continue;

            comm_pair_t *primary   = static_cast<comm_pair_t*>(item->data(Qt::UserRole).value<void*>());
            comm_pair_t *secondary = static_cast<comm_pair_t*>(item->data(Qt::UserRole + 1).value<void*>());

            /* Row matches if either primary or secondary pair matches the protocol filter */
            auto pairMatchesProtocol = [&](comm_pair_t *p) -> bool {
                if (!p) return false;
                if (p->top_protocol) {
                    QString proto = QString::fromUtf8(p->top_protocol);
                    if (enabled_protocols.contains(proto)) return true;
                }
                if (p->has_tcp && enabled_protocols.contains("TCP")) return true;
                if (p->has_udp && enabled_protocols.contains("UDP")) return true;
                return false;
            };

            bool matches = true;  /* default: show if no filter */
            if (!enabled_protocols.isEmpty())
                matches = pairMatchesProtocol(primary) || pairMatchesProtocol(secondary);

            item->setCheckState(matches ? Qt::Checked : Qt::Unchecked);
        }

        connect(m_pairListWidget, &QListWidget::itemChanged, this, &MainWindow::onPairListItemChanged);
        syncTableCheckboxesFromPairList();
        updateVisiblePairsFromWidgets();
        if (m_circleWidget) {
            m_circleWidget->update();
        }
    }
}

/* =====================================================
 * ConnectionPopup implementation
 * =====================================================
 */

/* Human-readable name for a 16-bit EtherType value (Ethernet II frames) */
static QString macEtherTypeName(guint16 et)
{
    switch (et) {
        case 0x0800: return "IPv4";
        case 0x0806: return "ARP";
        case 0x0835: return "RARP";
        case 0x86DD: return "IPv6";
        case 0x8100: return "VLAN (802.1Q)";
        case 0x88A8: return "QinQ (802.1ad)";
        case 0x8847: return "MPLS Unicast";
        case 0x8848: return "MPLS Multicast";
        case 0x8809: return "LACP / Slow Protocols";
        case 0x88CC: return "LLDP";
        case 0x888E: return "802.1X (EAPOL)";
        case 0x88E5: return "MACsec (802.1AE)";
        case 0x88F5: return "MRP";
        case 0x9100: return "QinQ (old)";
        default:     return QString();
    }
}

/* Human-readable name for an LLC DSAP value (IEEE 802.3 frames) */
static QString macLlcSapName(guint8 dsap)
{
    switch (dsap & 0xFE) {  /* mask off I/G bit, same as packet_analyzer.c */
        case 0x00: return "Null SAP";
        case 0x02: return "LLC Sub-layer Mgmt";
        case 0x06: return "ARPANET IP";
        case 0x42: return "STP / Spanning Tree";
        case 0xAA: return "SNAP";
        case 0xE0: return "Novell IPX";
        case 0xF0: return "NetBIOS";
        case 0xFE: return "OSI";
        default:   return QString();
    }
}

static QString portServiceName(quint16 port)
{
    switch (port) {
        case 20:   return "FTP-Data";
        case 21:   return "FTP";
        case 22:   return "SSH";
        case 23:   return "Telnet";
        case 25:   return "SMTP";
        case 53:   return "DNS";
        case 67: case 68: return "DHCP";
        case 80:   return "HTTP";
        case 88:   return "Kerberos";
        case 110:  return "POP3";
        case 123:  return "NTP";
        case 135:  return "MS-RPC";
        case 143:  return "IMAP";
        case 161:  return "SNMP";
        case 389:  return "LDAP";
        case 443:  return "HTTPS";
        case 445:  return "SMB";
        case 993:  return "IMAPS";
        case 995:  return "POP3S";
        case 1433: return "MSSQL";
        case 3306: return "MySQL";
        case 3389: return "RDP";
        case 5060: return "SIP";
        case 5432: return "PostgreSQL";
        case 5900: return "VNC";
        case 8080: return "HTTP-Proxy";
        case 8443: return "HTTPS-Alt";
        default:   return QString::number(port);
    }
}

/* Returns true if top_protocol is a Layer-2 non-IP protocol that should
 * show the L2 info card (QTextEdit) rather than the port table.        */
bool ConnectionPopup::isLayer2Protocol(const gchar *proto)
{
    if (!proto || !*proto) return false;
    static const char *l2protos[] = {
        "STP", "RSTP", "MSTP", "PVST", "PVST+",
        "LLDP", "LACP", "EAPOL", "EAP", "MACsec",
        "VTP", "CDP", "DTP", "PAGP", "LLC",
        "ARP", "RARP",
        NULL
    };
    for (int i = 0; l2protos[i]; i++) {
        if (g_strcmp0(proto, l2protos[i]) == 0)
            return true;
    }
    return false;
}

/* Forward declaration — defined after the ConnectionPopup constructor */
static QString extractRawMAC(const QString &addr);

ConnectionPopup::ConnectionPopup(comm_pair_t *pair, comm_pair_t *reversePair, gboolean useMAC, QWidget *parent)
    : QWidget(parent, Qt::Popup | Qt::FramelessWindowHint)
    , m_pair(pair)
    , m_reversePair(reversePair)
    , m_useMAC(useMAC)
    , m_table(nullptr)
    , m_macTable(nullptr)
    , m_macProgressBar(nullptr)
    , m_wifiInfoEdit(nullptr)
    , m_l2InfoEdit(nullptr)
    , m_autoCloseTimer(nullptr)
    , m_headerLabel(nullptr)
    , m_contextMenuActive(false)
    , m_scoreBtn(nullptr)
    , m_graphHealthScore(0.5)
    , m_graphAnomalyScore(0.0)
    , m_graphResponseTimeMs(-1.0)
    , m_graphThroughputBps(0.0)
{
    /* NOTE: Do NOT use WA_DeleteOnClose here.  QMenu::exec() runs a nested
     * event loop; if the auto-close timer fires during that loop and triggers
     * deletion, the destructor runs while showContextMenu() is still on the
     * call stack → use-after-free / SIGABRT.  Instead we use hide()+deleteLater()
     * for safe deferred destruction.                                             */
    setMouseTracking(true);

    /* Styling — theme-aware */
    bool dark = isDarkTheme();
    if (dark) {
        setStyleSheet(
            "ConnectionPopup {"
            "  background: #2b2b2b;"
            "  border: 1px solid #555;"
            "  border-radius: 6px;"
            "}"
        );
    } else {
        setStyleSheet(
            "ConnectionPopup {"
            "  background: #f8f8f8;"
            "  border: 1px solid #b0b0b0;"
            "  border-radius: 6px;"
            "}"
        );
    }

    QVBoxLayout *layout = new QVBoxLayout(this);
    layout->setContentsMargins(8, 8, 8, 8);
    layout->setSpacing(6);

    /* Header row: Source ↔ Destination label  +  (optional) Score button */
    QString srcDisplay = pair->resolved_src ? QString::fromUtf8(pair->resolved_src) : QString::fromUtf8(pair->src_addr);
    QString dstDisplay = pair->resolved_dst ? QString::fromUtf8(pair->resolved_dst) : QString::fromUtf8(pair->dst_addr);
    if (dark) {
        m_headerLabel = new QLabel(
            QString("<b style='color:#e0e0e0;'>%1</b>"
                    " <span style='color:#888;'>&harr;</span> "
                    "<b style='color:#e0e0e0;'>%2</b>")
                .arg(srcDisplay.toHtmlEscaped())
                .arg(dstDisplay.toHtmlEscaped()),
            this
        );
        m_headerLabel->setStyleSheet("QLabel { color: #e0e0e0; font-size: 12px; padding: 2px 0; }");
    } else {
        m_headerLabel = new QLabel(
            QString("<b style='color:#222;'>%1</b>"
                    " <span style='color:#888;'>&harr;</span> "
                    "<b style='color:#222;'>%2</b>")
                .arg(srcDisplay.toHtmlEscaped())
                .arg(dstDisplay.toHtmlEscaped()),
            this
        );
        m_headerLabel->setStyleSheet("QLabel { color: #222; font-size: 12px; padding: 2px 0; }");
    }
    m_headerLabel->setTextFormat(Qt::RichText);

    m_scoreBtn = new QPushButton("Calculating\u2026", this);
    m_scoreBtn->setFixedHeight(22);
    m_scoreBtn->setEnabled(false);
    m_scoreBtn->setToolTip("Show TCP Health and Anomaly score breakdown for this connection");
    m_scoreBtn->setVisible(false);  /* shown only in graph view — made visible by onLineClicked */
    if (dark) {
        m_scoreBtn->setStyleSheet(
            "QPushButton { background:#3a5a3a; color:#8eff8e; border:1px solid #4a7a4a;"
            " border-radius:3px; padding:2px 8px; font-size:11px; font-weight:bold; }"
            "QPushButton:hover { background:#4a6a4a; }");
    } else {
        m_scoreBtn->setStyleSheet(
            "QPushButton { background:#e8f5e9; color:#2e7d32; border:1px solid #a5d6a7;"
            " border-radius:3px; padding:2px 8px; font-size:11px; font-weight:bold; }"
            "QPushButton:hover { background:#c8e6c9; }");
    }

    QWidget *headerRow = new QWidget(this);
    QHBoxLayout *headerRowLayout = new QHBoxLayout(headerRow);
    headerRowLayout->setContentsMargins(0, 0, 0, 0);
    headerRowLayout->setSpacing(6);
    headerRowLayout->addWidget(m_headerLabel, 1);
    headerRowLayout->addWidget(m_scoreBtn, 0);
    layout->addWidget(headerRow);

    if (pair->is_wifi) {
        /* ---- Wi-Fi mode: rich HTML info card instead of port table ---- */
        m_wifiInfoEdit = new QTextEdit(this);
        m_wifiInfoEdit->setReadOnly(true);
        m_wifiInfoEdit->setContextMenuPolicy(Qt::CustomContextMenu);
        connect(m_wifiInfoEdit, &QTextEdit::customContextMenuRequested,
                this, &ConnectionPopup::showWifiContextMenu);
        if (dark) {
            m_wifiInfoEdit->setStyleSheet(
                "QTextEdit {"
                "  background: #333; color: #e0e0e0;"
                "  border: none; font-size: 11px; padding: 4px;"
                "}");
        } else {
            m_wifiInfoEdit->setStyleSheet(
                "QTextEdit {"
                "  background: #fff; color: #222;"
                "  border: none; font-size: 11px; padding: 4px;"
                "}");
        }
        layout->addWidget(m_wifiInfoEdit, 1);
        populateWifiInfo();

        /* "Apply Filter" button at the bottom */
        QPushButton *filterBtn = new QPushButton("Apply Filter in Wireshark", this);
        if (dark) {
            filterBtn->setStyleSheet(
                "QPushButton {"
                "  background: #0078d4; color: white; border: none;"
                "  border-radius: 4px; padding: 5px 12px; font-size: 11px; font-weight: bold;"
                "}"
                "QPushButton:hover { background: #1a8ae8; }");
        } else {
            filterBtn->setStyleSheet(
                "QPushButton {"
                "  background: #0078d4; color: white; border: none;"
                "  border-radius: 4px; padding: 5px 12px; font-size: 11px; font-weight: bold;"
                "}"
                "QPushButton:hover { background: #1a8ae8; }");
        }
        connect(filterBtn, &QPushButton::clicked, this, &ConnectionPopup::applyWifiFilter);
        layout->addWidget(filterBtn);

        resize(420, 410);
    } else if (!pair->is_wifi && (pair->is_mac || isLayer2Protocol(pair->top_protocol))) {
        /* ---- Layer-2 mode: protocol breakdown table (synchronous, same UX as IP mode) ----
         * Covers all MAC-mode pairs (even if top_protocol is "Unknown" or "Ethernet")
         * AND any IP-mode pair whose protocol is an explicit L2 type (ARP, STP, etc.) */
        m_macTable = new QTableWidget(this);
        m_macTable->setColumnCount(5);
        m_macTable->setHorizontalHeaderLabels(
            QStringList() << "EtherType" << "SAP/SNAP" << "Name" << "Packets" << "% of Total");
        m_macTable->setSelectionBehavior(QAbstractItemView::SelectRows);
        m_macTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
        m_macTable->setContextMenuPolicy(Qt::CustomContextMenu);
        m_macTable->horizontalHeader()->setStretchLastSection(false);
        m_macTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
        m_macTable->verticalHeader()->setVisible(false);
        m_macTable->setAlternatingRowColors(true);
        m_macTable->setColumnWidth(0, 88);   /* EtherType */
        m_macTable->setColumnWidth(1, 100);  /* SAP/SNAP  */
        /* column 2 (Name) stretches */
        m_macTable->setColumnWidth(3, 68);   /* Packets   */
        m_macTable->setColumnWidth(4, 72);   /* %         */
        if (dark) {
            m_macTable->setStyleSheet(
                "QTableWidget { background:#2b2b2b; color:#e0e0e0; gridline-color:#444; border:none; font-size:11px; }"
                "QTableWidget::item { padding: 4px 8px; }"
                "QTableWidget::item:alternate { background: #333; }"
                "QTableWidget::item:hover { background: #1a3a5a; color: #fff; }"
                "QTableWidget::item:selected { background:#0078d4; color:white; }"
                "QHeaderView::section { background:#333; color:#ccc; border:1px solid #555; padding:4px; font-weight:bold; font-size:10px; }");
        } else {
            m_macTable->setStyleSheet(
                "QTableWidget { background:#fff; color:#222; gridline-color:#ccc; border:none; font-size:11px; }"
                "QTableWidget::item { padding: 4px 8px; }"
                "QTableWidget::item:alternate { background: #f5f5f5; }"
                "QTableWidget::item:hover { background: #e3f2fd; color: #111; }"
                "QTableWidget::item:selected { background:#0078d4; color:white; }"
                "QHeaderView::section { background:#e8e8e8; color:#333; border:1px solid #c0c0c0; padding:4px; font-weight:bold; font-size:10px; }");
        }
        connect(m_macTable, &QTableWidget::customContextMenuRequested,
                this, &ConnectionPopup::onMacTableContextMenu);
        layout->addWidget(m_macTable, 1);

        /* Phase 1 (instant): show a "Scanning…" placeholder so the popup
         * appears immediately without waiting for the packet scan.
         * Phase 2 (deferred): QTimer::singleShot(0) schedules populateMacTable()
         * on the next event-loop tick so Qt can paint the window first.        */
        {
            m_macTable->setRowCount(1);
            auto *ph = new QTableWidgetItem("Scanning packets\xe2\x80\xa6");
            ph->setTextAlignment(Qt::AlignCenter);
            ph->setFlags(Qt::ItemIsEnabled);
            m_macTable->setSpan(0, 0, 1, 5);
            m_macTable->setItem(0, 0, ph);
        }
        /* Thin animated busy-bar sits below the table while the scan runs */
        m_macProgressBar = new QProgressBar(this);
        m_macProgressBar->setRange(0, 0);       /* indeterminate / marquee mode */
        m_macProgressBar->setTextVisible(false);
        m_macProgressBar->setFixedHeight(5);    /* just a slim stripe */
        m_macProgressBar->setStyleSheet(
            "QProgressBar {"
            "  border: none; border-radius: 2px;"
            "  background: transparent;"
            "}"
            "QProgressBar::chunk {"
            "  border-radius: 2px;"
            "  background: qlineargradient(x1:0,y1:0,x2:1,y2:0,"
            "    stop:0 #0078d4, stop:1 #60cdff);"
            "}");
        layout->addWidget(m_macProgressBar);

        resize(500, 145);  /* compact: title + table header + placeholder row + bar */

        QTimer::singleShot(0, this, [this]() { populateMacTable(); });
    } else {
        /* ---- Standard mode: port/session table ---- */
        m_table = new QTableWidget(this);
        m_table->setColumnCount(5);
        m_table->setHorizontalHeaderLabels(QStringList() << "Protocol" << "Port" << "Name" << "Packets" << "% of Total");
        m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
        m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
        m_table->setContextMenuPolicy(Qt::CustomContextMenu);
        m_table->horizontalHeader()->setStretchLastSection(true);
        m_table->verticalHeader()->setVisible(false);
        m_table->setAlternatingRowColors(true);
        m_table->setMouseTracking(true);

        /* Theme-aware table styling */
        if (dark) {
            m_table->setStyleSheet(
                "QTableWidget {"
                "  background: #333;"
                "  color: #e0e0e0;"
                "  gridline-color: #555;"
                "  border: none;"
                "  font-size: 11px;"
                "}"
                "QTableWidget::item {"
                "  padding: 4px 8px;"
                "}"
                "QTableWidget::item:alternate {"
                "  background: #383838;"
                "}"
                "QTableWidget::item:hover {"
                "  background: #e3f2fd;"
                "  color: #111;"
                "}"
                "QTableWidget::item:selected {"
                "  background: #0078d4;"
                "  color: white;"
                "}"
                "QHeaderView::section {"
                "  background: #3a3a3a;"
                "  color: #ccc;"
                "  border: 1px solid #555;"
                "  padding: 4px;"
                "  font-weight: bold;"
                "  font-size: 10px;"
                "}"
            );
        } else {
            m_table->setStyleSheet(
                "QTableWidget {"
                "  background: #fff;"
                "  color: #222;"
                "  gridline-color: #d0d0d0;"
                "  border: none;"
                "  font-size: 11px;"
                "}"
                "QTableWidget::item {"
                "  padding: 4px 8px;"
                "}"
                "QTableWidget::item:alternate {"
                "  background: #f5f5f5;"
                "}"
                "QTableWidget::item:hover {"
                "  background: #e3f2fd;"
                "  color: #111;"
                "}"
                "QTableWidget::item:selected {"
                "  background: #0078d4;"
                "  color: white;"
                "}"
                "QHeaderView::section {"
                "  background: #e8e8e8;"
                "  color: #333;"
                "  border: 1px solid #c0c0c0;"
                "  padding: 4px;"
                "  font-weight: bold;"
                "  font-size: 10px;"
                "}"
            );
        }

        connect(m_table, &QTableWidget::customContextMenuRequested, this, &ConnectionPopup::showContextMenu);
        layout->addWidget(m_table);
        populateTable();

        int rows = m_table->rowCount();
        int tableHeight = qMin(rows * 30 + 40, 300);
        resize(480, tableHeight + 60);
    }

    /* Auto-close timer: starts on leaveEvent, cancelled on enterEvent */
    m_autoCloseTimer = new QTimer(this);
    m_autoCloseTimer->setSingleShot(true);
    m_autoCloseTimer->setInterval(1000);  /* 1 second grace period */
    connect(m_autoCloseTimer, &QTimer::timeout, this, [this]() {
        if (m_contextMenuActive) return;   /* Don't destroy while menu is open */
        hide();
        deleteLater();
    });
}

ConnectionPopup::~ConnectionPopup()
{
}

/* ── Score breakdown dialog (opened by the Score button) ───────────────────
 * Shows a human-readable table of every signal that contributed to the TCP
 * Health score and the Anomaly score for this specific connection.           */
void ConnectionPopup::showScoreBtnCalculating()
{
    if (!m_scoreBtn) return;
    m_scoreBtn->setText("Calculating\u2026");
    m_scoreBtn->setEnabled(false);
    m_scoreBtn->setVisible(true);
}

void ConnectionPopup::setGraphScores(qreal healthScore, qreal anomalyScore,
                                      const QList<GraphWidget::ScoreFactor> &healthFactors,
                                      const QList<GraphWidget::ScoreFactor> &anomalyFactors,
                                      qreal responseTimeMs,
                                      qreal throughputBps,
                                      guint32 winMin,
                                      guint32 winMax,
                                      gdouble winAvg,
                                      guint32 zeroWinCount,
                                      gdouble zeroWinMaxDurMs)
{
    m_graphHealthScore    = healthScore;
    m_graphAnomalyScore   = anomalyScore;
    m_graphResponseTimeMs = responseTimeMs;
    m_graphThroughputBps  = throughputBps;
    m_healthFactors  = healthFactors;
    m_anomalyFactors = anomalyFactors;

    /* Pre-compute stats from m_pair while it is guaranteed valid.
     * The button lambda must not access m_pair — it can become dangling
     * by the time the user clicks (new capture file, pair refresh, etc.). */
    m_hasTcpData = m_pair && m_pair->has_tcp;
    m_rttMin = m_rttAvg = m_rttMax = -1.0;
    m_fwdBps = m_revBps = 0.0;

    if (m_pair && m_pair->has_tcp && m_pair->dst_ports) {
        capture_file *cfm = (capture_file *)plugin_if_get_capture_file(
            extract_capture_file, NULL);
        if (cfm) {
            quint16 topTcpPort = 0;
            guint64 topTcpCount = 0;
            GHashTableIter rpit; gpointer rpk, rpv;
            g_hash_table_iter_init(&rpit, m_pair->dst_ports);
            while (g_hash_table_iter_next(&rpit, &rpk, &rpv)) {
                port_stats_t *ps = (port_stats_t *)rpv;
                if (ps && ps->is_tcp && ps->count > topTcpCount) {
                    topTcpCount = ps->count;
                    topTcpPort  = (quint16)GPOINTER_TO_UINT(rpk);
                }
            }
            if (topTcpPort > 0) {
                tcp_stat_info_t *ti = packet_analyzer_extract_tcp_stat_info(
                    cfm, m_pair->src_addr, m_pair->dst_addr, topTcpPort,
                    m_pair->is_mac ? TRUE : FALSE);
                if (ti && ti->found && ti->rtt_count > 0) {
                    m_rttMin = ti->rtt_min_ms;
                    m_rttAvg = ti->rtt_sum_ms / (qreal)ti->rtt_count;
                    m_rttMax = ti->rtt_max_ms;
                }
                packet_analyzer_free_tcp_stat_info(ti);
            }
        }
    }
    if (m_rttAvg < 0.0 && responseTimeMs >= 0.0)
        m_rttAvg = responseTimeMs;

    /* TCP window stats — use pre-computed edge values passed from GraphWidget.
     * These are the same values used for edge colouring, so the score dialog
     * and the edge colour always agree. */
    m_winMin          = winMin;
    m_winMax          = winMax;
    m_winAvg          = winAvg;
    m_zeroWinCount    = zeroWinCount;
    m_zeroWinMaxDurMs = zeroWinMaxDurMs;

    if (m_pair && m_pair->first_ts > 0.0) {
        qreal dur = m_pair->last_ts - m_pair->first_ts;
        if (dur > 0.001) m_fwdBps = (qreal)m_pair->byte_count / dur;
    }
    if (m_reversePair && m_reversePair->first_ts > 0.0) {
        qreal dur = m_reversePair->last_ts - m_reversePair->first_ts;
        if (dur > 0.001) m_revBps = (qreal)m_reversePair->byte_count / dur;
    }

    if (m_scoreBtn) {
        m_scoreBtn->setText("Score");
        m_scoreBtn->setEnabled(true);
        m_scoreBtn->setVisible(true);
    }

    /* Disconnect any previous connection before wiring up the new lambda.
     * Without this, each call to setGraphScores() stacks another slot, so
     * clicking the button fires the old lambda(s) too — potentially with
     * stale m_pair state from earlier connections. */
    disconnect(m_scoreBtn, &QPushButton::clicked, nullptr, nullptr);
    connect(m_scoreBtn, &QPushButton::clicked, this, [this]() {
        bool dark = isDarkTheme();

        auto *dlg = new QDialog(this);
        dlg->setAttribute(Qt::WA_DeleteOnClose);
        dlg->setWindowTitle("Score Breakdown");
        dlg->setMinimumSize(420, 300);
        dlg->resize(520, 420);
        dlg->setSizeGripEnabled(true);

        QVBoxLayout *dlgLayout = new QVBoxLayout(dlg);

        auto *browser = new QTextEdit(dlg);
        browser->setReadOnly(true);
        if (dark) {
            browser->setStyleSheet("QTextEdit { background:#2b2b2b; color:#e0e0e0; border:none; font-size:12px; }");
        } else {
            browser->setStyleSheet("QTextEdit { background:#fff; color:#222; border:none; font-size:12px; }");
        }

        /* Helper: health label + colour */
        auto healthLabel = [](qreal hs) -> QString {
            if      (hs >= 0.75) return "<span style='color:#27ae60;'>&#9646; Healthy</span>";
            else if (hs >= 0.50) return "<span style='color:#f1c40f;'>&#9646; Moderate</span>";
            else if (hs >= 0.28) return "<span style='color:#e67e22;'>&#9646; Degraded</span>";
            else                 return "<span style='color:#e74c3c;'>&#9646; Unhealthy</span>";
        };
        auto anomalyLabel = [](qreal as) -> QString {
            if      (as <= 0.12) return "<span style='color:#27ae60;'>&#9646; Clean</span>";
            else if (as <= 0.30) return "<span style='color:#f1c40f;'>&#9646; Noteworthy</span>";
            else if (as <= 0.55) return "<span style='color:#e67e22;'>&#9646; Suspicious</span>";
            else                 return "<span style='color:#e74c3c;'>&#9646; Anomalous</span>";
        };

        auto buildTable = [dark](const QList<GraphWidget::ScoreFactor> &factors, bool isHealth) -> QString {
            QString html;
            html += "<table width='100%' cellspacing='0' cellpadding='4' "
                    "style='border-collapse:collapse; font-size:12px;'>";
            html += QString("<tr style='background:%1;'>"
                            "<th align='left' style='border-bottom:1px solid %2; padding:4px 6px;'>Signal</th>"
                            "<th align='right' style='border-bottom:1px solid %2; padding:4px 6px; width:80px;'>Change</th>"
                            "</tr>")
                    .arg(dark ? "#3a3a3a" : "#f0f0f0")
                    .arg(dark ? "#555"    : "#ccc");

            for (const GraphWidget::ScoreFactor &f : factors) {
                if (f.delta == 0.0) {
                    /* Separator / note row */
                    html += QString("<tr><td colspan='2' style='color:%1; font-style:italic; "
                                    "padding:4px 6px; border-bottom:1px solid %2;'>%3</td></tr>")
                            .arg(dark ? "#888" : "#666")
                            .arg(dark ? "#444" : "#ddd")
                            .arg(f.description.toHtmlEscaped());
                    continue;
                }
                /* For health: positive delta = green, negative = red.
                 * For anomaly: positive delta = red (more anomalous).    */
                bool isGood = isHealth ? (f.delta > 0) : (f.delta < 0);
                QString deltaStr = (f.delta > 0 ? "+" : "") +
                                   QString::number((int)qRound(f.delta * 100)) + "%";
                QString color = isGood ? (dark ? "#6edd6e" : "#27ae60")
                                       : (dark ? "#ff7070" : "#c0392b");
                html += QString("<tr><td style='padding:3px 6px; border-bottom:1px solid %1;'>%2</td>"
                                "<td align='right' style='padding:3px 6px; border-bottom:1px solid %1;"
                                " color:%3; font-weight:bold;'>%4</td></tr>")
                        .arg(dark ? "#3a3a3a" : "#eeeeee")
                        .arg(f.description.toHtmlEscaped())
                        .arg(color)
                        .arg(deltaStr);
            }
            html += "</table>";
            return html;
        };

        QString headingStyle = QString("font-size:13px; font-weight:bold; color:%1; "
                                       "margin-top:10px; margin-bottom:4px;")
                               .arg(dark ? "#e0e0e0" : "#222");
        QString baselineNote = QString("<p style='color:%1; font-size:11px; margin:4px 0;'>"
                                       "Baseline: 50% (adjusted by signals below)</p>")
                               .arg(dark ? "#888" : "#777");

        /* ── Format helpers for metrics ── */
        auto fmtRtt = [](qreal ms) -> QString {
            if (ms < 0) return "<i style='color:#888;'>N/A</i>";
            if (ms < 1.0)  return QString("<b>%1 ms</b>").arg(ms, 0, 'f', 2);
            if (ms < 10.0) return QString("<b>%1 ms</b>").arg(ms, 0, 'f', 1);
            return QString("<b>%1 ms</b>").arg(qRound(ms));
        };
        auto fmtTp = [](qreal bps) -> QString {
            if (bps <= 0) return "<i style='color:#888;'>N/A</i>";
            if (bps >= 1e9)  return QString("<b>%1 GB/s</b>").arg(bps / 1e9, 0, 'f', 2);
            if (bps >= 1e6)  return QString("<b>%1 MB/s</b>").arg(bps / 1e6, 0, 'f', 2);
            if (bps >= 1000) return QString("<b>%1 KB/s</b>").arg(bps / 1000.0, 0, 'f', 1);
            return QString("<b>%1 B/s</b>").arg((int)bps);
        };
        auto rttQual = [](qreal ms) -> const char* {
            if (ms < 0)   return "";
            if (ms <   5) return " &nbsp;<small>(Very Fast)</small>";
            if (ms <  50) return " &nbsp;<small>(Fast)</small>";
            if (ms < 200) return " &nbsp;<small>(Moderate)</small>";
            if (ms < 500) return " &nbsp;<small>(Slow)</small>";
            return " &nbsp;<small>(Very Slow)</small>";
        };
        auto tpQual = [](qreal bps) -> const char* {
            if (bps <= 0)       return "";
            if (bps <   10000)  return " &nbsp;<small>(Minimal)</small>";
            if (bps <  100000)  return " &nbsp;<small>(Low)</small>";
            if (bps < 1000000)  return " &nbsp;<small>(Moderate)</small>";
            if (bps < 10000000) return " &nbsp;<small>(High)</small>";
            return " &nbsp;<small>(Very High)</small>";
        };

        QString html;
        html += "<html><body style='font-family:sans-serif; margin:8px;'>";

        /* ── Connection Metrics section ── */
        QString labelColor = dark ? "#aaa" : "#555";

        /* RTT and throughput were pre-computed in setGraphScores() while
         * m_pair was valid — use the stored members directly. */
        qreal rttMin = m_rttMin, rttAvg = m_rttAvg, rttMax = m_rttMax;
        qreal fwdBps = m_fwdBps, revBps = m_revBps;

        auto cell = [&](const QString &subLabel, const QString &value) -> QString {
            return QString("<td style='text-align:center; padding:2px 4px;'>"
                           "<span style='font-size:10px; color:%1;'>%2</span><br/>%3</td>")
                   .arg(labelColor, subLabel, value);
        };

        html += QString("<p style='%1'>Connection Metrics</p>").arg(headingStyle);
        html += "<table width='100%' cellspacing='0' cellpadding='0'>";

        /* Response Time row */
        html += QString("<tr>"
                        "<td width='26%' style='color:%1; font-size:11px; vertical-align:middle;'"
                        ">Response Time</td>")
                .arg(labelColor);
        html += cell("Min", rttMin >= 0.0 ? fmtRtt(rttMin) : "<i style='color:#888;'>N/A</i>");
        html += cell("Avg", fmtRtt(rttAvg) + QLatin1String(rttQual(rttAvg)));
        html += cell("Max", rttMax >= 0.0 ? fmtRtt(rttMax) : "<i style='color:#888;'>N/A</i>");
        html += "</tr>";

        /* Throughput row */
        html += QString("<tr style='margin-top:4px;'>"
                        "<td style='color:%1; font-size:11px; vertical-align:middle;'>Throughput</td>")
                .arg(labelColor);
        html += cell("&#8594;&nbsp;fwd", fwdBps > 0.0
                     ? fmtTp(fwdBps) : "<i style='color:#888;'>N/A</i>");
        html += cell("&#8644;&nbsp;combined", m_graphThroughputBps > 0.0
                     ? fmtTp(m_graphThroughputBps) + QLatin1String(tpQual(m_graphThroughputBps))
                     : "<i style='color:#888;'>N/A</i>");
        html += cell("&#8592;&nbsp;rev", revBps > 0.0
                     ? fmtTp(revBps) : "<i style='color:#888;'>N/A</i>");
        html += "</tr>";

        /* TCP Window row — only when window data was collected */
        if (m_winMin != G_MAXUINT32) {
            auto fmtWin = [](guint32 b) -> QString {
                if (b == G_MAXUINT32) return "<i style='color:#888;'>N/A</i>";
                if (b >= 1024u*1024u) return QString("<b>%1 MB</b>").arg(b / (1024*1024));
                if (b >= 1024u)       return QString("<b>%1 KB</b>").arg(b / 1024.0, 0, 'f', 1);
                return QString("<b>%1 B</b>").arg(b);
            };
            html += QString("<tr style='margin-top:4px;'>"
                            "<td style='color:%1; font-size:11px; vertical-align:middle;'>TCP Window</td>")
                    .arg(labelColor);
            html += cell("Min", fmtWin(m_winMin));
            html += cell("Avg", m_winAvg > 0.0 ? fmtWin((guint32)m_winAvg)
                                               : "<i style='color:#888;'>N/A</i>");
            html += cell("Max", fmtWin(m_winMax));
            html += "</tr>";

            if (m_zeroWinCount > 0) {
                QString alertColor = dark ? "#ff7070" : "#c0392b";
                html += QString("<tr><td colspan='4' style='padding:4px 6px;'>"
                                "<span style='color:%1; font-weight:bold;'>&#9888; Zero-window: "
                                "%2 event(s)")
                        .arg(alertColor)
                        .arg(m_zeroWinCount);
                if (m_zeroWinMaxDurMs > 0.0) {
                    QString durStr = m_zeroWinMaxDurMs < 10.0
                        ? QString::number(m_zeroWinMaxDurMs, 'f', 1)
                        : QString::number(qRound(m_zeroWinMaxDurMs));
                    html += QString(" &mdash; max stall <b>%1 ms</b>").arg(durStr);
                }
                html += " (receiver overwhelmed; sender was stalled)</span></td></tr>";
            }
        }

        html += "</table>";
        html += "<hr style='margin:12px 0; border:0; border-top:1px solid ";
        html += (dark ? "#444" : "#ddd");
        html += ";'/>";

        /* ── TCP Health section ── */
        html += QString("<p style='%1'>TCP Health Score: %2%  &nbsp; %3</p>")
                .arg(headingStyle)
                .arg(qRound(m_graphHealthScore * 100))
                .arg(healthLabel(m_graphHealthScore));
        if (!m_hasTcpData) {
            html += QString("<p style='color:%1; font-style:italic;'>"
                            "No TCP traffic observed on this pair — score is neutral (50%).</p>")
                    .arg(dark ? "#888" : "#666");
        } else {
            html += baselineNote;
            html += buildTable(m_healthFactors, true);
        }

        html += "<hr style='margin:12px 0; border:0; border-top:1px solid ";
        html += (dark ? "#444" : "#ddd");
        html += ";'/>";

        /* ── Anomaly Score section ── */
        html += QString("<p style='%1'>Anomaly Score: %2%  &nbsp; %3</p>")
                .arg(headingStyle)
                .arg(qRound(m_graphAnomalyScore * 100))
                .arg(anomalyLabel(m_graphAnomalyScore));
        if (m_anomalyFactors.isEmpty()) {
            html += QString("<p style='color:%1; font-style:italic;'>"
                            "No anomaly signals detected — connection appears normal.</p>")
                    .arg(dark ? "#888" : "#666");
        } else {
            html += QString("<p style='color:%1; font-size:11px; margin:4px 0;'>"
                            "Baseline: 0% (each signal adds to the score)</p>")
                    .arg(dark ? "#888" : "#777");
            html += buildTable(m_anomalyFactors, false);
        }

        html += QString("<p style='color:%1; font-size:10px; margin-top:12px;'>"
                        "Note: Scores are inferred from aggregate statistics (bytes, packets, ports).<br/>"
                        "TCP flag-level data (SYN/RST/FIN counts) is not available in this view.</p>")
                .arg(dark ? "#666" : "#999");

        html += "</body></html>";

        browser->setHtml(html);
        dlgLayout->addWidget(browser);

        auto *bbx = new QDialogButtonBox(QDialogButtonBox::Close, dlg);
        connect(bbx, &QDialogButtonBox::rejected, dlg, &QDialog::reject);
        dlgLayout->addWidget(bbx);

        dlg->exec();
    });
}

void ConnectionPopup::enterEvent(QEnterEvent *event)
{
    Q_UNUSED(event);
    /* Cancel auto-close when mouse enters */
    if (m_autoCloseTimer->isActive()) {
        m_autoCloseTimer->stop();
    }
}

void ConnectionPopup::leaveEvent(QEvent *event)
{
    Q_UNUSED(event);
    /* Don't start auto-close when mouse moves to the context menu */
    if (m_contextMenuActive) return;
    m_autoCloseTimer->start();
}

void ConnectionPopup::populateTable()
{
    if (!m_pair)
        return;

    /* ---- ICMP / ICMPv6: show type breakdown instead of empty port table ---- */
    bool isICMP   = m_pair->top_protocol && g_strcmp0(m_pair->top_protocol, "ICMP")   == 0;
    bool isICMPv6 = m_pair->top_protocol && g_strcmp0(m_pair->top_protocol, "ICMPv6") == 0;

    if (isICMP || isICMPv6) {
        m_table->setColumnCount(3);
        m_table->setHorizontalHeaderLabels(
            QStringList() << "ICMP Type" << "Packets" << "% of Total");
        m_table->horizontalHeader()->setStretchLastSection(true);

        capture_file *cf = (capture_file *)plugin_if_get_capture_file(
            extract_capture_file, NULL);
        guint64 totalPackets = m_pair->packet_count +
                               (m_reversePair ? m_reversePair->packet_count : 0);

        if (cf) {
            icmp_info_t *icmpInfo = packet_analyzer_extract_icmp_info(
                cf, m_pair->src_addr, m_pair->dst_addr, m_pair->is_mac, isICMPv6);

            if (icmpInfo && icmpInfo->found && icmpInfo->type_labels) {
                int row = 0;
                m_table->setRowCount((int)g_list_length(icmpInfo->type_labels));
                for (GList *l = icmpInfo->type_labels; l; l = l->next, row++) {
                    const gchar *label = (const gchar *)l->data;
                    guint count = GPOINTER_TO_UINT(
                        g_hash_table_lookup(icmpInfo->type_counts, label));

                    m_table->setItem(row, 0, new QTableWidgetItem(
                        QString::fromUtf8(label)));

                    QTableWidgetItem *pktItem = new QTableWidgetItem(
                        QString::number(count));
                    pktItem->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
                    m_table->setItem(row, 1, pktItem);

                    double pct = totalPackets > 0 ? 100.0 * count / totalPackets : 0.0;
                    QTableWidgetItem *pctItem = new QTableWidgetItem(
                        QString::number(pct, 'f', 1) + "%");
                    pctItem->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
                    m_table->setItem(row, 2, pctItem);
                }
                m_table->setColumnWidth(0, 200);
                m_table->setColumnWidth(1, 70);
            } else {
                /* Found ICMP protocol but no type data — show total only */
                m_table->setRowCount(1);
                m_table->setItem(0, 0, new QTableWidgetItem(isICMPv6 ? "ICMPv6" : "ICMP"));
                m_table->setItem(0, 1, new QTableWidgetItem(
                    QString::number(totalPackets)));
                m_table->setItem(0, 2, new QTableWidgetItem("100.0%"));
            }
            if (icmpInfo) packet_analyzer_free_icmp_info(icmpInfo);
        }
        return;   /* skip port-table logic below */
    }

    /* Merge port data from BOTH directions (A→B and B→A) so the popup
     * shows a complete picture regardless of which directional pair was
     * picked by the click-hit-test.  We use a QMap keyed by port number
     * so that identical ports from both directions are combined.          */
    struct MergedPort {
        quint64 packets = 0;
        bool isTcp = false;
        bool isUdp = false;
    };
    QMap<quint16, MergedPort> merged;
    guint64 totalPackets = m_pair->packet_count;
    if (m_reversePair)
        totalPackets += m_reversePair->packet_count;

    /* Helper lambda: iterate one pair's dst_ports into 'merged' */
    auto mergePorts = [&](comm_pair_t *p) {
        if (!p || !p->dst_ports) return;
        GHashTableIter port_iter;
        gpointer port_key, port_value;
        g_hash_table_iter_init(&port_iter, p->dst_ports);
        while (g_hash_table_iter_next(&port_iter, &port_key, &port_value)) {
            quint16 port = (quint16)GPOINTER_TO_UINT(port_key);
            port_stats_t *ps = (port_stats_t *)port_value;
            if (!ps || port == 0 || ps->count == 0) continue;

            MergedPort &mp = merged[port];
            mp.packets += ps->count;
            if (ps->is_tcp) mp.isTcp = true;
            if (ps->is_udp) mp.isUdp = true;
        }
    };

    mergePorts(m_pair);
    mergePorts(m_reversePair);

    /* Build PortEntry list from merged map */
    struct PortEntry {
        QString protocol;
        quint16 port;
        quint64 packets;
        bool isTcp;
        bool isUdp;
    };
    QList<PortEntry> entries;

    for (auto it = merged.constBegin(); it != merged.constEnd(); ++it) {
        const MergedPort &mp = it.value();
        QString proto;
        if (mp.isTcp && mp.isUdp) {
            proto = "TCP+UDP";
        } else if (mp.isTcp) {
            proto = "TCP";
        } else if (mp.isUdp) {
            proto = "UDP";
        } else {
            proto = "-";
        }

        PortEntry entry;
        entry.protocol = proto;
        entry.port = it.key();
        entry.packets = mp.packets;
        entry.isTcp = mp.isTcp;
        entry.isUdp = mp.isUdp;
        entries.append(entry);
    }

    /* Sort by packet count descending */
    std::sort(entries.begin(), entries.end(), [](const PortEntry &a, const PortEntry &b) {
        return a.packets > b.packets;
    });

    /* Populate table */
    m_table->setRowCount(static_cast<int>(entries.size()));
    m_rowData.clear();

    for (int i = 0; i < entries.size(); i++) {
        const PortEntry &e = entries[i];

        /* Store row data for context menu (includes per-port protocol) */
        RowData rd;
        rd.protocol = e.protocol;
        rd.port = e.port;
        rd.packets = e.packets;
        rd.isTcp = e.isTcp;
        rd.isUdp = e.isUdp;
        m_rowData.append(rd);

        m_table->setItem(i, 0, new QTableWidgetItem(e.protocol));
        m_table->setItem(i, 1, new QTableWidgetItem(QString::number(e.port)));
        m_table->setItem(i, 2, new QTableWidgetItem(portServiceName(e.port)));

        QTableWidgetItem *pktItem = new QTableWidgetItem(QString::number(e.packets));
        pktItem->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
        m_table->setItem(i, 3, pktItem);

        double pct = totalPackets > 0 ? (100.0 * e.packets / totalPackets) : 0;
        QTableWidgetItem *pctItem = new QTableWidgetItem(QString::number(pct, 'f', 1) + "%");
        pctItem->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
        m_table->setItem(i, 4, pctItem);
    }

    /* Adjust column widths */
    m_table->setColumnWidth(0, 70);
    m_table->setColumnWidth(1, 70);
    m_table->setColumnWidth(2, 100);
    m_table->setColumnWidth(3, 70);
}

/* ------------------------------------------------------------------ */
/* Wi-Fi info card (replaces port table for 802.11 pairs)             */
/* ------------------------------------------------------------------ */

QString ConnectionPopup::wifiPhyName(guint8 phy)
{
    switch (phy) {
    case 1:  return "802.11 (FHSS)";
    case 2:  return "802.11 (IR)";
    case 3:  return "802.11 (DSSS)";
    case 4:  return "802.11b (HR-DSSS)";
    case 5:  return "802.11a (OFDM)";
    case 6:  return "802.11g (ERP)";
    case 7:  return "802.11n (HT)";
    case 8:  return "802.11ac (VHT)";
    case 9:  return "802.11ax (HE)";
    case 10: return "802.11be (EHT)";
    default: return QString();
    }
}

QString ConnectionPopup::wifiReasonCodeText(guint16 reason)
{
    switch (reason) {
    case 1:  return "Unspecified reason";
    case 2:  return "Previous authentication no longer valid";
    case 3:  return "Station leaving / has left";
    case 4:  return "Disassociated due to inactivity";
    case 5:  return "AP unable to handle all associated STAs";
    case 6:  return "Class 2 frame from non-authenticated STA";
    case 7:  return "Class 3 frame from non-associated STA";
    case 8:  return "Station leaving / has left BSS";
    case 9:  return "STA requesting (re)assoc not authenticated";
    case 10: return "Disassociated: power capability unacceptable";
    case 11: return "Disassociated: supported channels unacceptable";
    case 12: return "Disassociated: BSS transition management";
    case 13: return "Invalid information element";
    case 14: return "MIC failure";
    case 15: return "4-way handshake timeout";
    case 16: return "Group key handshake timeout";
    case 17: return "IE in 4-way handshake different from (re)assoc";
    case 18: return "Invalid group cipher";
    case 19: return "Invalid pairwise cipher";
    case 20: return "Invalid AKMP";
    case 23: return "IEEE 802.1X authentication failed";
    case 24: return "Cipher suite rejected (security policy)";
    case 34: return "Disassociated: TDLS direct-link teardown";
    case 39: return "Disassociated: peer STA not in OBSS";
    case 45: return "Peer STA not a TDLS peer STA";
    case 46: return "Unspecified QoS-related reason";
    default:
        if (reason == 0) return QString();
        return QString("Reason %1").arg(reason);
    }
}

void ConnectionPopup::populateWifiInfo()
{
    if (!m_pair || !m_wifiInfoEdit)
        return;

    bool dark = isDarkTheme();
    QString headingColor = dark ? "#90caf9" : "#1565c0";
    QString textColor    = dark ? "#e0e0e0" : "#222";
    QString dimColor     = dark ? "#999"    : "#666";
    QString valColor     = dark ? "#c8e6c9" : "#1b5e20";
    QString warnColor    = dark ? "#ffcc80" : "#e65100";
    QString alertColor   = dark ? "#ef9a9a" : "#b71c1c";

    /* Merge stats from both directions */
    comm_pair_t *p = m_pair;
    comm_pair_t *rp = m_reversePair;
    guint64 totalFrames = p->packet_count + (rp ? rp->packet_count : 0);
    guint64 totalBytes  = p->byte_count   + (rp ? rp->byte_count   : 0);
    guint32 totalRetries = p->retry_count  + (rp ? rp->retry_count  : 0);

    /* RSSI: prefer the pair that has samples */
    gint32 rssiSum   = p->rssi_sum   + (rp ? rp->rssi_sum   : 0);
    guint32 rssiCount = p->rssi_count + (rp ? rp->rssi_count : 0);
    gint16 rssiMin = p->rssi_count ? p->rssi_min : 0;
    gint16 rssiMax = p->rssi_count ? p->rssi_max : 0;
    if (rp && rp->rssi_count) {
        if (!p->rssi_count || rp->rssi_min < rssiMin) rssiMin = rp->rssi_min;
        if (!p->rssi_count || rp->rssi_max > rssiMax) rssiMax = rp->rssi_max;
    }

    /* Frame type totals from both directions */
    guint32 mgmt = p->mgmt_frame_count + (rp ? rp->mgmt_frame_count : 0);
    guint32 ctrl = p->ctrl_frame_count + (rp ? rp->ctrl_frame_count : 0);
    guint32 data = p->data_frame_count + (rp ? rp->data_frame_count : 0);

    /* Management subtypes */
    guint32 beacons    = p->beacon_count      + (rp ? rp->beacon_count      : 0);
    guint32 probeReqs  = p->probe_req_count   + (rp ? rp->probe_req_count   : 0);
    guint32 probeResps = p->probe_resp_count  + (rp ? rp->probe_resp_count  : 0);
    guint32 auths      = p->auth_count        + (rp ? rp->auth_count        : 0);
    guint32 deauths    = p->deauth_count      + (rp ? rp->deauth_count      : 0);
    guint32 assocReqs  = p->assoc_req_count   + (rp ? rp->assoc_req_count   : 0);
    guint32 assocResps = p->assoc_resp_count  + (rp ? rp->assoc_resp_count  : 0);
    guint32 reassocReqs= p->reassoc_req_count + (rp ? rp->reassoc_req_count : 0);
    guint32 disassocs  = p->disassoc_count    + (rp ? rp->disassoc_count    : 0);

    /* Reason codes (prefer non-zero) */
    guint16 deauthReason  = p->deauth_reason  ? p->deauth_reason  : (rp ? rp->deauth_reason  : 0);
    guint16 disassocReason= p->disassoc_reason? p->disassoc_reason: (rp ? rp->disassoc_reason : 0);

    /* Build HTML */
    QString html = QString("<div style='color:%1; font-size:11px;'>").arg(textColor);

    /* ---- Network Identity ---- */
    html += QString("<h3 style='color:%1; margin:4px 0 2px 0; font-size:13px;'>Network</h3>").arg(headingColor);
    html += "<table cellpadding='2'>";
    if (p->wifi_ssid) {
        html += QString("<tr><td style='color:%1;'>SSID:</td>"
                        "<td style='color:%2;'><b>%3</b></td></tr>")
                    .arg(dimColor).arg(valColor)
                    .arg(QString::fromUtf8(p->wifi_ssid).toHtmlEscaped());
    }
    if (p->wifi_bssid) {
        html += QString("<tr><td style='color:%1;'>BSSID:</td>"
                        "<td style='font-family:monospace;'>%2</td></tr>")
                    .arg(dimColor)
                    .arg(QString::fromUtf8(p->wifi_bssid).toHtmlEscaped());
    }
    if (p->wifi_channel > 0) {
        html += QString("<tr><td style='color:%1;'>Channel:</td>"
                        "<td><b>%2</b></td></tr>")
                    .arg(dimColor).arg(p->wifi_channel);
    }
    QString phyName = wifiPhyName(p->wifi_phy);
    if (phyName.isEmpty() && rp) phyName = wifiPhyName(rp->wifi_phy);
    if (!phyName.isEmpty()) {
        html += QString("<tr><td style='color:%1;'>Standard:</td>"
                        "<td><b>%2</b></td></tr>")
                    .arg(dimColor).arg(phyName.toHtmlEscaped());
    }
    html += "</table>";

    /* ---- Signal Quality ---- */
    if (rssiCount > 0) {
        int avgRSSI = (int)(rssiSum / (gint32)rssiCount);
        QString quality;
        QString qualColor;
        if (avgRSSI >= -55) {
            quality = "Excellent"; qualColor = dark ? "#81c784" : "#2e7d32";
        } else if (avgRSSI >= -65) {
            quality = "Good"; qualColor = dark ? "#aed581" : "#558b2f";
        } else if (avgRSSI >= -75) {
            quality = "Fair"; qualColor = warnColor;
        } else {
            quality = "Poor"; qualColor = alertColor;
        }
        html += QString("<h3 style='color:%1; margin:8px 0 2px 0; font-size:13px;'>Signal</h3>").arg(headingColor);
        html += "<table cellpadding='2'>";
        html += QString("<tr><td style='color:%1;'>Quality:</td>"
                        "<td style='color:%2; font-weight:bold;'>%3</td></tr>")
                    .arg(dimColor).arg(qualColor).arg(quality);
        html += QString("<tr><td style='color:%1;'>Average RSSI:</td>"
                        "<td><b>%2 dBm</b></td></tr>")
                    .arg(dimColor).arg(avgRSSI);
        html += QString("<tr><td style='color:%1;'>Range:</td>"
                        "<td>%2 to %3 dBm (%4 samples)</td></tr>")
                    .arg(dimColor).arg(rssiMin).arg(rssiMax).arg(rssiCount);
        html += "</table>";
    }

    /* ---- Traffic Statistics ---- */
    html += QString("<h3 style='color:%1; margin:8px 0 2px 0; font-size:13px;'>Traffic</h3>").arg(headingColor);
    html += "<table cellpadding='2'>";
    html += QString("<tr><td style='color:%1;'>Frames:</td>"
                    "<td><b>%2</b></td></tr>")
                .arg(dimColor).arg(totalFrames);
    /* Format bytes nicely */
    QString bytesStr;
    if (totalBytes >= 1048576)
        bytesStr = QString("%1 MB").arg(totalBytes / 1048576.0, 0, 'f', 1);
    else if (totalBytes >= 1024)
        bytesStr = QString("%1 KB").arg(totalBytes / 1024.0, 0, 'f', 1);
    else
        bytesStr = QString("%1 B").arg(totalBytes);
    html += QString("<tr><td style='color:%1;'>Bytes:</td>"
                    "<td><b>%2</b></td></tr>")
                .arg(dimColor).arg(bytesStr);
    if (totalRetries > 0) {
        double retryPct = totalFrames > 0 ? (100.0 * totalRetries / totalFrames) : 0;
        QString retryColor = (retryPct > 10.0) ? alertColor : ((retryPct > 5.0) ? warnColor : textColor);
        html += QString("<tr><td style='color:%1;'>Retries:</td>"
                        "<td style='color:%2;'><b>%3</b> (%4%)</td></tr>")
                    .arg(dimColor).arg(retryColor)
                    .arg(totalRetries)
                    .arg(QString::number(retryPct, 'f', 1));
    }
    html += "</table>";

    /* ---- Frame Type Breakdown ---- */
    if (mgmt + ctrl + data > 0) {
        html += QString("<h3 style='color:%1; margin:8px 0 2px 0; font-size:13px;'>Frame Types</h3>").arg(headingColor);
        html += "<table cellpadding='2'>";
        if (data > 0)
            html += QString("<tr><td style='color:%1;'>Data:</td><td><b>%2</b></td></tr>").arg(dimColor).arg(data);
        if (mgmt > 0)
            html += QString("<tr><td style='color:%1;'>Management:</td><td><b>%2</b></td></tr>").arg(dimColor).arg(mgmt);
        if (ctrl > 0)
            html += QString("<tr><td style='color:%1;'>Control:</td><td><b>%2</b></td></tr>").arg(dimColor).arg(ctrl);
        html += "</table>";
    }

    /* ---- Management Events ---- */
    bool hasMgmtEvents = (beacons || probeReqs || probeResps || auths || deauths ||
                          assocReqs || assocResps || reassocReqs || disassocs);
    if (hasMgmtEvents) {
        html += QString("<h3 style='color:%1; margin:8px 0 2px 0; font-size:13px;'>Management Events</h3>").arg(headingColor);
        html += "<table cellpadding='2'>";
        if (beacons > 0)
            html += QString("<tr><td style='color:%1;'>Beacons:</td><td>%2</td></tr>").arg(dimColor).arg(beacons);
        if (probeReqs > 0)
            html += QString("<tr><td style='color:%1;'>Probe Requests:</td><td>%2</td></tr>").arg(dimColor).arg(probeReqs);
        if (probeResps > 0)
            html += QString("<tr><td style='color:%1;'>Probe Responses:</td><td>%2</td></tr>").arg(dimColor).arg(probeResps);
        if (assocReqs > 0)
            html += QString("<tr><td style='color:%1;'>Association Req:</td><td>%2</td></tr>").arg(dimColor).arg(assocReqs);
        if (assocResps > 0)
            html += QString("<tr><td style='color:%1;'>Association Resp:</td><td>%2</td></tr>").arg(dimColor).arg(assocResps);
        if (reassocReqs > 0)
            html += QString("<tr><td style='color:%1;'>Reassociation Req:</td><td>%2</td></tr>").arg(dimColor).arg(reassocReqs);
        if (auths > 0)
            html += QString("<tr><td style='color:%1;'>Authentication:</td><td>%2</td></tr>").arg(dimColor).arg(auths);
        if (deauths > 0) {
            QString reasonText = wifiReasonCodeText(deauthReason);
            QString extra = reasonText.isEmpty() ? "" : QString(" &mdash; <i>%1</i>").arg(reasonText.toHtmlEscaped());
            html += QString("<tr><td style='color:%1;'>Deauthentication:</td>"
                            "<td style='color:%2;'><b>%3</b>%4</td></tr>")
                        .arg(dimColor).arg(alertColor).arg(deauths).arg(extra);
        }
        if (disassocs > 0) {
            QString reasonText = wifiReasonCodeText(disassocReason);
            QString extra = reasonText.isEmpty() ? "" : QString(" &mdash; <i>%1</i>").arg(reasonText.toHtmlEscaped());
            html += QString("<tr><td style='color:%1;'>Disassociation:</td>"
                            "<td style='color:%2;'><b>%3</b>%4</td></tr>")
                        .arg(dimColor).arg(warnColor).arg(disassocs).arg(extra);
        }
        html += "</table>";
    }

    html += "</div>";
    m_wifiInfoEdit->setHtml(html);
}

void ConnectionPopup::showWifiContextMenu(const QPoint &pos)
{
    QMenu menu;  /* NOT parented to 'this' &mdash; must stay stack-safe when
                   plugin_if_apply_filter re-enters the event loop and
                   triggers our deferred destruction.                    */
    menu.setStyleSheet(pcMenuStyleSheet());

    QAction *filterAction = menu.addAction("Apply Wi-Fi Filter in Wireshark");

    m_contextMenuActive = true;
    m_autoCloseTimer->stop();

    QAction *selected = menu.exec(m_wifiInfoEdit->mapToGlobal(pos));
    m_contextMenuActive = false;

    if (selected == filterAction) {
        applyWifiFilter();
    } else {
        m_autoCloseTimer->start();
    }
}

/* Extract the raw MAC address from a possibly-resolved string.
 * Wireshark's label_value() can return forms like:
 *   "Cisco_a9:38:40 (00:1b:2b:a9:38:40)"   →  00:1b:2b:a9:38:40
 *   "Broadcast (ff:ff:ff:ff:ff:ff)"           →  ff:ff:ff:ff:ff:ff
 *   "00:1b:2b:a9:38:40"                      →  00:1b:2b:a9:38:40  (already raw)
 */
static QString extractRawMAC(const QString &addr)
{
    /* If the string contains "(xx:xx:xx:xx:xx:xx)", grab the MAC from inside */
    static QRegularExpression re("\\(([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})\\)");
    QRegularExpressionMatch m = re.match(addr);
    if (m.hasMatch())
        return m.captured(1);
    /* Already a bare MAC or something else — return as-is */
    return addr.trimmed();
}

void ConnectionPopup::applyWifiFilter()
{
    if (!m_pair) return;
    QString src = extractRawMAC(QString::fromUtf8(m_pair->src_addr));
    QString dst = extractRawMAC(QString::fromUtf8(m_pair->dst_addr));
    QString filter = QString("(wlan.addr == %1 && wlan.addr == %2)").arg(src).arg(dst);
    QByteArray fb = filter.toUtf8();
    QPointer<ConnectionPopup> guard(this);
    plugin_if_apply_filter(fb.constData(), true);
    if (!guard) return;   /* destroyed during event-loop re-entry */
    hide();
    deleteLater();
}

/* MAC-mode protocol breakdown table population (deferred via QTimer::singleShot).
 * Runs the full L2 packet scan and fills m_macTable with one row per unique
 * EtherType or LLC SAP pair.  Called from a zero-delay timer so the popup
 * window can render the "Scanning…" placeholder before this scan blocks.  */
void ConnectionPopup::populateMacTable()
{
    if (!m_pair || !m_macTable)
        return;

    /* Clear the placeholder row/span before populating with real data */
    m_macTable->clearSpans();
    m_macTable->setRowCount(0);

    /* Tier 2: honour performance setting */
    if (!m_enableL2Analysis) {
        auto *item = new QTableWidgetItem(
            "\u26a0  Layer-2 / LLC analysis is disabled in Settings \u2192 Performance.");
        item->setTextAlignment(Qt::AlignCenter);
        item->setFlags(Qt::ItemIsEnabled);
        m_macTable->setColumnCount(1);
        m_macTable->setRowCount(1);
        m_macTable->setItem(0, 0, item);
        if (m_macProgressBar) m_macProgressBar->hide();
        return;
    }

    capture_file *cf = (capture_file *)plugin_if_get_capture_file(
        extract_capture_file, NULL);
    if (!cf) return;

    /* Tier 3: check cache before running a full scan */
    QString cacheKey = AnalysisCache::l2Key(m_pair->src_addr, m_pair->dst_addr);
    l2_info_t *li = s_analysisCache.l2.value(cacheKey, nullptr);
    bool fromCache = (li != nullptr);
    if (!li) {
        li = packet_analyzer_extract_l2_info(cf, m_pair->src_addr, m_pair->dst_addr, TRUE);
        if (li) s_analysisCache.l2.insert(cacheKey, li);  /* store; cache owns from here */
    }
    if (!li) return;

    if (li->found) {
        struct MacEntry {
            QString  etherType;
            QString  sapSnap;
            QString  name;
            quint64  packets;
            bool     isEtherType;
            guint16  etherTypeVal;
            guint8   dsap, ssap;
        };
        QList<MacEntry> entries;
        quint64 tableTotal = 0;

        /* -- EtherType rows -- */
        if (li->ethertype_counts) {
            GHashTableIter it; gpointer k, v;
            g_hash_table_iter_init(&it, li->ethertype_counts);
            while (g_hash_table_iter_next(&it, &k, &v)) {
                const char *ks = (const char *)k;
                quint64 cnt   = (quint64)GPOINTER_TO_UINT(v);
                guint16 etVal = (guint16)strtoul(ks + 2, nullptr, 16);
                QString dispName = macEtherTypeName(etVal);
                MacEntry e;
                e.etherType    = QString::fromUtf8(ks);
                e.sapSnap      = "\xe2\x80\x94"; /* em-dash — */
                e.name         = dispName.isEmpty() ? QString::fromUtf8(ks) : dispName;
                e.packets      = cnt;
                e.isEtherType  = true;
                e.etherTypeVal = etVal;
                e.dsap = e.ssap = 0;
                entries << e;
                tableTotal += cnt;
            }
        }

        /* -- LLC rows -- */
        if (li->llc_counts) {
            GHashTableIter it; gpointer k, v;
            g_hash_table_iter_init(&it, li->llc_counts);
            while (g_hash_table_iter_next(&it, &k, &v)) {
                const char *ks = (const char *)k;  /* "0xDS/0xSS" */
                quint64 cnt    = (quint64)GPOINTER_TO_UINT(v);
                guint8 d = 0, s = 0;
                sscanf(ks, "0x%hhx/0x%hhx", &d, &s);
                QString sapName = macLlcSapName(d);
                MacEntry e;
                e.etherType    = "802.3";
                e.sapSnap      = QString::fromUtf8(ks);
                e.name         = sapName.isEmpty() ? QString::fromUtf8(ks) : sapName;
                e.packets      = cnt;
                e.isEtherType  = false;
                e.etherTypeVal = 0;
                e.dsap = d;
                e.ssap = s;
                entries << e;
                tableTotal += cnt;
            }
        }

        /* Sort descending by packet count */
        std::sort(entries.begin(), entries.end(),
                  [](const MacEntry &a, const MacEntry &b) {
                      return a.packets > b.packets; });

        /* Populate QTableWidget */
        m_macRowData.clear();
        m_macTable->setRowCount(entries.size());
        for (int r = 0; r < entries.size(); ++r) {
            const MacEntry &e = entries[r];
            auto *i0 = new QTableWidgetItem(e.etherType);
            auto *i1 = new QTableWidgetItem(e.sapSnap);
            auto *i2 = new QTableWidgetItem(e.name);
            auto *i3 = new QTableWidgetItem(QString::number(e.packets));
            i3->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
            double pct = tableTotal > 0
                         ? 100.0 * (double)e.packets / (double)tableTotal : 0.0;
            auto *i4 = new QTableWidgetItem(
                QString("%1 %").arg(pct, 0, 'f', 1));
            i4->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
            for (auto *it : {i0, i1, i2, i3, i4})
                it->setFlags(it->flags() & ~Qt::ItemIsEditable);
            m_macTable->setItem(r, 0, i0);
            m_macTable->setItem(r, 1, i1);
            m_macTable->setItem(r, 2, i2);
            m_macTable->setItem(r, 3, i3);
            m_macTable->setItem(r, 4, i4);
            MacRowData rd;
            rd.etherType    = e.etherType;
            rd.sapSnap      = e.sapSnap;
            rd.name         = e.name;
            rd.packets      = e.packets;
            rd.isEtherType  = e.isEtherType;
            rd.etherTypeVal = e.etherTypeVal;
            rd.dsap         = e.dsap;
            rd.ssap         = e.ssap;
            m_macRowData << rd;
        }
        m_macTable->resizeRowsToContents();
    }

    /* li is owned by the cache — never free here */

    /* Hide the busy-bar now that data has arrived */
    if (m_macProgressBar) {
        m_macProgressBar->hide();
        m_macProgressBar = nullptr;   /* widget is still owned by the layout / parent */
    }

    /* Resize the popup to exactly fit the table content now that we have
     * real row data.  Mirror the IP-mode formula: header + rows + margins. */
    {
        int hdrH  = m_macTable->horizontalHeader()->height();
        int rowsH = 0;
        for (int r = 0; r < m_macTable->rowCount(); r++)
            rowsH += m_macTable->rowHeight(r);
        /* Cap at 300 px of table content so the popup doesn't grow too tall */
        int tableH = qMin(hdrH + rowsH + 4, 300);
        /* 55 px covers: title label (~25) + layout top/bottom margins (~30) */
        resize(500, tableH + 55);
    }
}

void ConnectionPopup::populateL2Info()
{
    /* Phase 1 — instant: render basic protocol + MAC + traffic stats immediately,
     * then schedule Phase 2 (expensive packet scan) on the next event-loop tick
     * so the popup window appears without delay even on large captures.          */
    if (!m_pair || !m_l2InfoEdit)
        return;

    bool dark = isDarkTheme();
    QString headingColor = dark ? "#90caf9" : "#1565c0";
    QString textColor    = dark ? "#e0e0e0" : "#222";
    QString dimColor     = dark ? "#999"    : "#666";

    comm_pair_t *p  = m_pair;
    comm_pair_t *rp = m_reversePair;
    guint64 totalFrames = p->packet_count + (rp ? rp->packet_count : 0);
    guint64 totalBytes  = p->byte_count   + (rp ? rp->byte_count   : 0);

    QString proto = (p->top_protocol && *p->top_protocol)
                    ? QString::fromUtf8(p->top_protocol) : "Layer-2";

    QString html = QString("<div style='color:%1; font-size:11px;'>").arg(textColor);

    /* ---- Protocol ---- */
    html += QString("<h3 style='color:%1; margin:4px 0 2px 0; font-size:13px;'>Layer-2 Protocol</h3>").arg(headingColor);
    html += "<table cellpadding='2'>";
    html += QString("<tr><td style='color:%1;'>Protocol:</td>"
                    "<td><b>%2</b></td></tr>")
                .arg(dimColor).arg(proto.toHtmlEscaped());
    html += QString("<tr><td style='color:%1;'>Source MAC:</td>"
                    "<td style='font-family:monospace;'>%2</td></tr>")
                .arg(dimColor)
                .arg(QString::fromUtf8(p->src_addr).toHtmlEscaped());
    html += QString("<tr><td style='color:%1;'>Dest MAC:</td>"
                    "<td style='font-family:monospace;'>%2</td></tr>")
                .arg(dimColor)
                .arg(QString::fromUtf8(p->dst_addr).toHtmlEscaped());
    html += "</table>";

    /* ---- Traffic Statistics ---- */
    html += QString("<h3 style='color:%1; margin:8px 0 2px 0; font-size:13px;'>Traffic</h3>").arg(headingColor);
    html += "<table cellpadding='2'>";
    html += QString("<tr><td style='color:%1;'>Frames:</td>"
                    "<td><b>%2</b></td></tr>")
                .arg(dimColor).arg(totalFrames);

    QString bytesStr;
    if (totalBytes >= 1048576)
        bytesStr = QString("%1 MB").arg(totalBytes / 1048576.0, 0, 'f', 1);
    else if (totalBytes >= 1024)
        bytesStr = QString("%1 KB").arg(totalBytes / 1024.0, 0, 'f', 1);
    else
        bytesStr = QString("%1 B").arg(totalBytes);

    html += QString("<tr><td style='color:%1;'>Bytes:</td>"
                    "<td><b>%2</b></td></tr>")
                .arg(dimColor).arg(bytesStr);
    html += "</table>";

    /* ---- Placeholder — replaced by loadL2Extended() once scan completes ---- */
    html += QString("<p style='color:%1; font-size:10px; font-style:italic; margin-top:6px;'>"
                    "&#x231B;&nbsp;Analyzing frame details&hellip;</p>")
                .arg(dimColor);

    html += "</div>";
    m_l2InfoEdit->setHtml(html);

    /* Schedule Phase 2 on the next event-loop tick so the popup renders first */
    QTimer::singleShot(0, this, [this]() { loadL2Extended(); });
}

/* Phase 2 — deferred: perform the full-capture EtherType/LLC/VLAN scan and
 * re-render the info card with the complete data.  Runs after the popup is
 * visible so the UI stays responsive on large captures.
 * STP detail is intentionally omitted here — available via right-click menu. */
void ConnectionPopup::loadL2Extended()
{
    if (!m_pair || !m_l2InfoEdit)
        return;

    bool dark = isDarkTheme();
    QString headingColor = dark ? "#90caf9" : "#1565c0";
    QString textColor    = dark ? "#e0e0e0" : "#222";
    QString dimColor     = dark ? "#999"    : "#666";
    QString valColor     = dark ? "#c8e6c9" : "#1b5e20";

    comm_pair_t *p  = m_pair;
    comm_pair_t *rp = m_reversePair;
    guint64 totalFrames = p->packet_count + (rp ? rp->packet_count : 0);
    guint64 totalBytes  = p->byte_count   + (rp ? rp->byte_count   : 0);

    QString proto = (p->top_protocol && *p->top_protocol)
                    ? QString::fromUtf8(p->top_protocol) : "Layer-2";

    /* Re-build the complete HTML from scratch — cleaner than patching live HTML */
    QString html = QString("<div style='color:%1; font-size:11px;'>").arg(textColor);

    /* ---- Protocol ---- */
    html += QString("<h3 style='color:%1; margin:4px 0 2px 0; font-size:13px;'>Layer-2 Protocol</h3>").arg(headingColor);
    html += "<table cellpadding='2'>";
    html += QString("<tr><td style='color:%1;'>Protocol:</td>"
                    "<td><b>%2</b></td></tr>")
                .arg(dimColor).arg(proto.toHtmlEscaped());
    html += QString("<tr><td style='color:%1;'>Source MAC:</td>"
                    "<td style='font-family:monospace;'>%2</td></tr>")
                .arg(dimColor)
                .arg(QString::fromUtf8(p->src_addr).toHtmlEscaped());
    html += QString("<tr><td style='color:%1;'>Dest MAC:</td>"
                    "<td style='font-family:monospace;'>%2</td></tr>")
                .arg(dimColor)
                .arg(QString::fromUtf8(p->dst_addr).toHtmlEscaped());
    html += "</table>";

    /* ---- Traffic Statistics ---- */
    html += QString("<h3 style='color:%1; margin:8px 0 2px 0; font-size:13px;'>Traffic</h3>").arg(headingColor);
    html += "<table cellpadding='2'>";
    html += QString("<tr><td style='color:%1;'>Frames:</td>"
                    "<td><b>%2</b></td></tr>")
                .arg(dimColor).arg(totalFrames);

    QString bytesStr;
    if (totalBytes >= 1048576)
        bytesStr = QString("%1 MB").arg(totalBytes / 1048576.0, 0, 'f', 1);
    else if (totalBytes >= 1024)
        bytesStr = QString("%1 KB").arg(totalBytes / 1024.0, 0, 'f', 1);
    else
        bytesStr = QString("%1 B").arg(totalBytes);

    html += QString("<tr><td style='color:%1;'>Bytes:</td>"
                    "<td><b>%2</b></td></tr>")
                .arg(dimColor).arg(bytesStr);
    html += "</table>";

    /* ---- EtherType / LLC / VLAN (full packet scan → protocol breakdown table) ---- */
    capture_file *cf = (capture_file *)plugin_if_get_capture_file(
        extract_capture_file, NULL);
    if (cf) {
        l2_info_t *li = packet_analyzer_extract_l2_info(
            cf, p->src_addr, p->dst_addr, TRUE);

        if (li && li->found) {
            /* Build a unified list of (EtherType or LLC) entries with counts,
             * then populate the m_macTable QTableWidget (shown below the text card). */
            struct MacEntry {
                QString  etherType;
                QString  sapSnap;
                QString  name;
                quint64  packets;
                bool     isEtherType;
                guint16  etherTypeVal;
                guint8   dsap, ssap;
            };
            QList<MacEntry> entries;
            quint64 tableTotal = 0;

            /* -- EtherType rows -- */
            if (li->ethertype_counts) {
                GHashTableIter it; gpointer k, v;
                g_hash_table_iter_init(&it, li->ethertype_counts);
                while (g_hash_table_iter_next(&it, &k, &v)) {
                    const char *ks = (const char *)k;
                    quint64 cnt   = (quint64)GPOINTER_TO_UINT(v);
                    guint16 etVal = (guint16)strtoul(ks + 2, nullptr, 16);
                    QString dispName = macEtherTypeName(etVal);
                    MacEntry e;
                    e.etherType   = QString::fromUtf8(ks);
                    e.sapSnap     = "\xe2\x80\x94"; /* em-dash — */
                    e.name        = dispName.isEmpty() ? QString::fromUtf8(ks) : dispName;
                    e.packets     = cnt;
                    e.isEtherType = true;
                    e.etherTypeVal= etVal;
                    e.dsap = e.ssap = 0;
                    entries << e;
                    tableTotal += cnt;
                }
            }

            /* -- LLC rows -- */
            if (li->llc_counts) {
                GHashTableIter it; gpointer k, v;
                g_hash_table_iter_init(&it, li->llc_counts);
                while (g_hash_table_iter_next(&it, &k, &v)) {
                    const char *ks = (const char *)k;  /* "0xDS/0xSS" */
                    quint64 cnt    = (quint64)GPOINTER_TO_UINT(v);
                    guint8 d = 0, s = 0;
                    sscanf(ks, "0x%hhx/0x%hhx", &d, &s);
                    QString sapName = macLlcSapName(d);
                    MacEntry e;
                    e.etherType   = "802.3";
                    e.sapSnap     = QString::fromUtf8(ks);
                    e.name        = sapName.isEmpty() ? QString::fromUtf8(ks) : sapName;
                    e.packets     = cnt;
                    e.isEtherType = false;
                    e.etherTypeVal= 0;
                    e.dsap = d;
                    e.ssap = s;
                    entries << e;
                    tableTotal += cnt;
                }
            }

            /* Sort descending by packet count */
            std::sort(entries.begin(), entries.end(),
                      [](const MacEntry &a, const MacEntry &b) {
                          return a.packets > b.packets; });

            /* Populate the MAC table widget */
            if (m_macTable && !entries.isEmpty()) {
                m_macRowData.clear();
                m_macTable->setRowCount(entries.size());
                for (int r = 0; r < entries.size(); ++r) {
                    const MacEntry &e = entries[r];
                    auto *i0 = new QTableWidgetItem(e.etherType);
                    auto *i1 = new QTableWidgetItem(e.sapSnap);
                    auto *i2 = new QTableWidgetItem(e.name);
                    auto *i3 = new QTableWidgetItem(QString::number(e.packets));
                    i3->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
                    double pct = tableTotal > 0
                                 ? 100.0 * (double)e.packets / (double)tableTotal : 0.0;
                    auto *i4 = new QTableWidgetItem(
                        QString("%1 %").arg(pct, 0, 'f', 1));
                    i4->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
                    for (auto *it : {i0, i1, i2, i3, i4})
                        it->setFlags(it->flags() & ~Qt::ItemIsEditable);
                    m_macTable->setItem(r, 0, i0);
                    m_macTable->setItem(r, 1, i1);
                    m_macTable->setItem(r, 2, i2);
                    m_macTable->setItem(r, 3, i3);
                    m_macTable->setItem(r, 4, i4);
                    MacRowData rd;
                    rd.etherType    = e.etherType;
                    rd.sapSnap      = e.sapSnap;
                    rd.name         = e.name;
                    rd.packets      = e.packets;
                    rd.isEtherType  = e.isEtherType;
                    rd.etherTypeVal = e.etherTypeVal;
                    rd.dsap         = e.dsap;
                    rd.ssap         = e.ssap;
                    m_macRowData << rd;
                }
                m_macTable->resizeRowsToContents();
                m_macTable->show();
            }

            /* VLAN IDs — keep in text card since they have no per-entry packet count */
            if (li->vlan_ids) {
                QStringList vlans;
                for (GList *v = li->vlan_ids; v; v = v->next)
                    if (v->data) vlans << QString::fromUtf8((const gchar *)v->data);
                if (!vlans.isEmpty()) {
                    html += QString("<h3 style='color:%1; margin:8px 0 2px 0; font-size:13px;'>VLAN IDs</h3>").arg(headingColor);
                    html += QString("<div style='color:%1; font-family:monospace;'>%2</div>")
                            .arg(valColor).arg(vlans.join(", ").toHtmlEscaped());
                }
            }
        }

        if (li) packet_analyzer_free_l2_info(li);
    }

    /* ── Right-click hint on the protocol table ──────────────────────────── */
    html += QString("<p style='color:%1; font-size:10px; font-style:italic; "
                    "margin-top:6px; padding-top:2px;'>"
                    "&#x2139;&nbsp;Right-click a row in the protocol table for filter "
                    "and detail options.</p>")
                .arg(dimColor);

    html += "</div>";
    m_l2InfoEdit->setHtml(html);
}

/* Right-click context menu for the MAC protocol breakdown table.
 * Offers "Apply Filter" for all rows, plus protocol-specific detail dialogs
 * for ARP, STP, LLDP, LACP, EAP, and MACsec rows. */
void ConnectionPopup::onMacTableContextMenu(const QPoint &pos)
{
    if (!m_macTable) return;
    int row = m_macTable->rowAt(pos.y());
    if (row < 0 || row >= m_macRowData.size()) return;
    const MacRowData &rd = m_macRowData[row];

    QMenu menu;
    menu.setStyleSheet(pcMenuStyleSheet());

    QAction *filterAct = menu.addAction("Apply Filter in Wireshark");
    menu.addSeparator();

    /* Protocol-specific detail action (NULL if no dialog available for this row) */
    QAction *detailAct = nullptr;
    if (rd.isEtherType) {
        switch (rd.etherTypeVal) {
            case 0x0806: detailAct = menu.addAction("ARP Information");           break;
            case 0x8100: detailAct = menu.addAction("VLAN (802.1Q) Information"); break;
            case 0x8809: detailAct = menu.addAction("LACP Information");          break;
            case 0x88CC: detailAct = menu.addAction("LLDP Information");          break;
            case 0x888E: detailAct = menu.addAction("802.1X (EAP) Information");  break;
            case 0x88E5: detailAct = menu.addAction("MACsec Information");        break;
            default: break;
        }
    } else {
        /* IEEE 802.3 LLC frame */
        switch (rd.dsap & 0xFE) {
            case 0x42: detailAct = menu.addAction("Spanning Tree (STP) Information"); break;
            default: break;
        }
    }

    m_contextMenuActive = true;
    m_autoCloseTimer->stop();
    QPointer<ConnectionPopup> guard(this);
    QAction *sel = menu.exec(m_macTable->mapToGlobal(pos));
    if (!guard) return;  /* popup was destroyed while menu was open */

    /* NOTE: Do NOT reset m_contextMenuActive here for action branches.
     * All info-dialog branches call hide()+deleteLater() themselves.
     * Resetting it here would let leaveEvent() restart the auto-close timer,
     * which can fire during the heavy packet scan inside showArpInfoDialog() etc.
     * and free 'this' before hide() is reached — causing SIGSEGV.
     * Only the "dismissed" branch resets the flag.  (Same pattern as showContextMenu.) */

    if (!sel) {
        /* User dismissed without selecting — reset guard and restart auto-close */
        m_contextMenuActive = false;
        m_autoCloseTimer->start();
        return;
    }

    if (sel == filterAct) {
        QString src = extractRawMAC(QString::fromUtf8(m_pair->src_addr));
        QString dst = extractRawMAC(QString::fromUtf8(m_pair->dst_addr));
        QString filter = QString("(eth.addr == %1 && eth.addr == %2)").arg(src).arg(dst);
        QByteArray fb = filter.toUtf8();
        QPointer<ConnectionPopup> guard2(this);
        plugin_if_apply_filter(fb.constData(), true);
        if (!guard2) return;
        hide();
        deleteLater();
        return;
    }

    if (sel == detailAct) {
        if (rd.isEtherType) {
            switch (rd.etherTypeVal) {
                case 0x0806: showArpInfoDialog();    break;
                case 0x8100: showVlanInfoDialog();   break;
                case 0x8809: showLacpInfoDialog();   break;
                case 0x88CC: showLldpInfoDialog();   break;
                case 0x888E: showEapInfoDialog();    break;
                case 0x88E5: showMacsecInfoDialog(); break;
                default: break;
            }
        } else if ((rd.dsap & 0xFE) == 0x42) {
            showStpInfoDialog();
        }
        /* Info dialog branches handle hide()+deleteLater() internally */
    }
}

void ConnectionPopup::showL2ContextMenu(const QPoint &pos)
{
    QMenu menu;  /* NOT parented to 'this' &mdash; must stay stack-safe when
                   plugin_if_apply_filter re-enters the event loop and
                   triggers our deferred destruction.                    */
    menu.setStyleSheet(pcMenuStyleSheet());

    QAction *filterAction = menu.addAction("Apply Filter in Wireshark");
    menu.addSeparator();

    QString proto = (m_pair && m_pair->top_protocol && *m_pair->top_protocol)
                    ? QString::fromUtf8(m_pair->top_protocol) : "";

    QAction *stpAction    = nullptr;
    QAction *lldpAction   = nullptr;
    QAction *lacpAction   = nullptr;
    QAction *eapAction    = nullptr;
    QAction *macsecAction = nullptr;

    if (proto == "STP" || proto == "RSTP" || proto == "MSTP" ||
        proto == "PVST" || proto == "PVST+") {
        stpAction = menu.addAction("Spanning Tree (STP) Information");
    } else if ((proto == "LLC" || proto == "Unknown") && m_pair) {
        /* STP runs over LLC DSAP=0x42 — probe LLC info to confirm before showing menu item */
        capture_file *cf_stpck = (capture_file *)plugin_if_get_capture_file(
            extract_capture_file, NULL);
        if (cf_stpck) {
            l2_info_t *li_stpck = packet_analyzer_extract_l2_info(
                cf_stpck, m_pair->src_addr, m_pair->dst_addr, TRUE);
            if (li_stpck && li_stpck->found && li_stpck->llc_dsap_ssap) {
                for (GList *lc = li_stpck->llc_dsap_ssap; lc && !stpAction; lc = lc->next) {
                    const gchar *sap = (const gchar *)lc->data;
                    if (sap && g_strstr_len(sap, -1, "STP"))
                        stpAction = menu.addAction("Spanning Tree (STP) Information");
                }
            }
            if (li_stpck) packet_analyzer_free_l2_info(li_stpck);
        }
    }

    if (proto == "LLDP")
        lldpAction = menu.addAction("LLDP Information");

    if (proto == "LACP")
        lacpAction = menu.addAction("LACP Information");

    if (proto == "EAPOL" || proto == "EAP")
        eapAction = menu.addAction("802.1X / EAP Information");

    if (proto == "MACsec")
        macsecAction = menu.addAction("MACsec Information");

    QAction *arpAction = nullptr;
    if (proto == "ARP" || proto == "RARP")
        arpAction = menu.addAction("ARP MAC/IP Mapping");

    m_contextMenuActive = true;
    m_autoCloseTimer->stop();

    QAction *selected = menu.exec(m_l2InfoEdit->mapToGlobal(pos));
    m_contextMenuActive = false;

    if (selected == filterAction) {
        QString src = extractRawMAC(QString::fromUtf8(m_pair->src_addr));
        QString dst = extractRawMAC(QString::fromUtf8(m_pair->dst_addr));
        QString filter = QString("(eth.addr == %1 && eth.addr == %2)").arg(src).arg(dst);
        QByteArray fb = filter.toUtf8();
        QPointer<ConnectionPopup> guard(this);
        plugin_if_apply_filter(fb.constData(), true);
        if (!guard) return;
        hide();
        deleteLater();
    } else if (stpAction    && selected == stpAction)    { showStpInfoDialog();   }
    else if   (lldpAction   && selected == lldpAction)   { showLldpInfoDialog();  }
    else if   (lacpAction   && selected == lacpAction)   { showLacpInfoDialog();  }
    else if   (eapAction    && selected == eapAction)    { showEapInfoDialog();   }
    else if   (macsecAction && selected == macsecAction) { showMacsecInfoDialog();}
    else if   (arpAction    && selected == arpAction)    { showArpInfoDialog();   }
    else {
        m_autoCloseTimer->start();
    }
}

void ConnectionPopup::showContextMenu(const QPoint &pos)
{
    int row = m_table->rowAt(pos.y());
    if (row < 0 || row >= m_rowData.size())
        return;

    m_table->selectRow(row);

    QMenu menu;  /* NOT parented to 'this' &mdash; must stay stack-safe when
                   plugin_if_apply_filter re-enters the event loop and
                   triggers our deferred destruction.                    */
    menu.setStyleSheet(pcMenuStyleSheet());

    /* ── Wireshark section ── */
    menu.addSection("Wireshark");
    QAction *filterAction     = menu.addAction("Apply Filter in Wireshark");
    QAction *followAction     = menu.addAction("Follow TCP Stream");
    QAction *throughputAction = menu.addAction("TCP Throughput Graph");
    QAction *rttAction        = menu.addAction("TCP Round-Trip Time Graph");

    /* Disable TCP-only actions for non-TCP rows */
    const RowData &rd = m_rowData[row];
    bool isTCP = rd.isTcp;
    followAction->setEnabled(isTCP);
    throughputAction->setEnabled(isTCP);
    rttAction->setEnabled(isTCP);
    if (!isTCP) {
        followAction->setText("Follow TCP Stream (TCP only)");
        throughputAction->setText("TCP Throughput Graph (TCP only)");
        rttAction->setText("TCP Round-Trip Time Graph (TCP only)");
    }

    /* ── PacketCircle section ── */
    menu.addSection("PacketCircle");

    /* Map the row's port to the appropriate protocol info function.     */
    struct ProtoMatch { int id; QString label; };
    auto matchProto = [&]() -> ProtoMatch {
        quint16 p  = rd.port;
        bool tcp   = rd.isTcp;
        bool udp   = rd.isUdp;
        if (tcp && p == 22)                                                 return { 13, "SSH / SFTP / SCP" };
        if ((tcp||udp) && p == 443)                                         return {  1, "TLS / HTTPS" };
        if (tcp && p == 80)                                                 return {  2, "HTTP" };
        if (tcp && (p == 445 || p == 135))                                  return {  3, "SMB / DCE-RPC" };
        if ((tcp||udp) && p == 88)                                          return {  4, "Kerberos" };
        if (tcp && (p == 25 || p == 465 || p == 587))                      return {  5, "SMTP / Email" };
        if (tcp && (p == 143 || p == 993))                                  return {  5, "IMAP / Email" };
        if (tcp && (p == 110 || p == 995))                                  return {  5, "POP3 / Email" };
        if (tcp && (p == 1433 || p == 3306 || p == 5432))                  return {  6, "SQL Database" };
        if ((tcp||udp) && (p == 5060 || p == 5061))                        return {  7, "VoIP / SIP" };
        if (udp && (p == 67 || p == 68))                                    return {  8, "DHCP" };
        if ((udp||tcp) && p == 53)                                          return {  9, "DNS" };
        if (tcp && (p == 389 || p == 636 || p == 3268 || p == 3269))       return { 10, "LDAP" };
        if ((udp||tcp) && (p == 161 || p == 162))                          return { 11, "SNMP" };
        if ((udp||tcp) && (p == 514 || p == 601 || p == 6514))             return { 12, "Syslog" };
        if (tcp && (p == 21 || p == 20 || p == 990))                       return { 14, "FTP" };
        if (tcp && (p == 23 || p == 992))                                   return { 15, "Telnet" };
        if (udp && p == 137)                                                return { 16, "NBNS" };
        if (udp && p == 138)                                                return { 17, "NetBIOS Datagram" };
        if (tcp && p == 139)                                                return { 18, "NetBIOS Session (NBSS)" };
        return { 0, {} };
    };
    ProtoMatch pm = matchProto();

    /* Protocol info action (port-specific, optional) */
    QAction *protoDirectAction = nullptr;
    if (pm.id > 0) {
        protoDirectAction = menu.addAction(pm.label + " Protocol Information");
        if (!m_enableDeepInspection) {
            protoDirectAction->setEnabled(false);
            protoDirectAction->setText(pm.label + " Protocol Information (disabled in Settings)");
        }
    }

    /* Generic TCP/UDP transport info */
    QAction *tcpStatAction = nullptr;
    QAction *udpStatAction = nullptr;
    if (isTCP) {
        tcpStatAction = menu.addAction("TCP Transport Details\u2026");
        if (!m_enableTransportStats) {
            tcpStatAction->setEnabled(false);
            tcpStatAction->setText("TCP Transport Details\u2026 (disabled in Settings)");
        }
    } else if (!isTCP && rd.isUdp) {
        udpStatAction = menu.addAction("UDP Transport Details\u2026");
        if (!m_enableTransportStats) {
            udpStatAction->setEnabled(false);
            udpStatAction->setText("UDP Transport Details\u2026 (disabled in Settings)");
        }
    }

    QAction *supportedProtosAction = menu.addAction("Supported Protocols\u2026");

    /* Guard: prevent auto-close timer while QMenu::exec()'s event loop runs */
    m_contextMenuActive = true;
    m_autoCloseTimer->stop();

    QAction *selected = menu.exec(m_table->viewport()->mapToGlobal(pos));

    if (!selected) {
        /* User dismissed without selecting; reset guard and restart auto-close */
        m_contextMenuActive = false;
        m_autoCloseTimer->start();
        return;
    }
    /* NOTE: Do NOT reset m_contextMenuActive here.  All action branches call
     * deleteLater() themselves.                                               */

    if (selected == filterAction) {
        applyFilterForRow(row);
    } else if (selected == followAction) {
        followTCPStreamForRow(row);
    } else if (selected == throughputAction) {
        openTcpStreamGraph(row, "Throughput");
    } else if (selected == rttAction) {
        openTcpStreamGraph(row, "Round Trip Time");
    } else if (pm.id > 0 && selected == protoDirectAction) {
        switch (pm.id) {
            case  1: showTlsInfoForRow(row);      break;
            case  2: showHttpInfoForRow(row);     break;
            case  3: showSmbInfoForRow(row);      break;
            case  4: showKerberosInfoForRow(row); break;
            case  5: showEmailInfoForRow(row);    break;
            case  6: showSqlInfoForRow(row);      break;
            case  7: showVoipInfoForRow(row);     break;
            case  8: showDhcpInfoForRow(row);     break;
            case  9: showDnsInfoForRow(row);      break;
            case 10: showLdapInfoForRow(row);     break;
            case 11: showSnmpInfoForRow(row);     break;
            case 12: showSyslogInfoForRow(row);   break;
            case 13: showSshInfoForRow(row);      break;
            case 14: showFtpInfoForRow(row);      break;
            case 15: showTelnetInfoForRow(row);   break;
            case 16: showNbnsInfoForRow(row);     break;
            case 17: showNbdgmInfoForRow(row);    break;
            case 18: showNbssInfoForRow(row);     break;
            default: break;
        }
    } else if (selected == tcpStatAction) {
        showTcpStatInfoForRow(row);
    } else if (selected == udpStatAction) {
        showUdpStatInfoForRow(row);
    } else if (selected == supportedProtosAction) {
        showProtocolInfoBrowserForRow(row);
    }
}

/* ── triggerInfoForPort / triggerTransportDetails ──────────────────────────
 * Called from the main-window table right-click menu to open a protocol info
 * or transport-details dialog directly, without ever showing this popup.
 *
 * The popup is constructed by the caller but kept hidden; hide() is therefore
 * a no-op and deleteLater() performs safe deferred cleanup after the dialog
 * returns from its exec() call.                                              */
void ConnectionPopup::triggerInfoForPort(quint16 port, int protoId)
{
    /* Find the m_rowData row whose port matches, then dispatch */
    for (int i = 0; i < m_rowData.size(); i++) {
        if (m_rowData[i].port != port) continue;
        switch (protoId) {
            case  1: showTlsInfoForRow(i);      return;
            case  2: showHttpInfoForRow(i);     return;
            case  3: showSmbInfoForRow(i);      return;
            case  4: showKerberosInfoForRow(i); return;
            case  5: showEmailInfoForRow(i);    return;
            case  6: showSqlInfoForRow(i);      return;
            case  7: showVoipInfoForRow(i);     return;
            case  8: showDhcpInfoForRow(i);     return;
            case  9: showDnsInfoForRow(i);      return;
            case 10: showLdapInfoForRow(i);     return;
            case 11: showSnmpInfoForRow(i);     return;
            case 12: showSyslogInfoForRow(i);   return;
            case 13: showSshInfoForRow(i);      return;
            case 14: showFtpInfoForRow(i);      return;
            case 15: showTelnetInfoForRow(i);   return;
            case 16: showNbnsInfoForRow(i);     return;
            case 17: showNbdgmInfoForRow(i);    return;
            case 18: showNbssInfoForRow(i);     return;
            default: break;
        }
        return;
    }
    /* Port not found (can happen if capture has no traffic on that port yet) */
    deleteLater();
}

void ConnectionPopup::triggerTransportDetails(bool forTcp)
{
    for (int i = 0; i < m_rowData.size(); i++) {
        if (forTcp && m_rowData[i].isTcp) {
            showTcpStatInfoForRow(i);
            return;
        } else if (!forTcp && m_rowData[i].isUdp) {
            showUdpStatInfoForRow(i);
            return;
        }
    }
    deleteLater();
}

/* ── Protocol Information Browser ──────────────────────────────────────────
 * Presents all supported protocol info dialogs in a single picker window.
 * The user selects a protocol from the list, then the corresponding existing
 * info dialog opens (same code path as before — just reached from one place). */
void ConnectionPopup::showProtocolInfoBrowserForRow(int row)
{
    if (row < 0 || row >= m_rowData.size() || !m_pair)
        return;

    const RowData &rd = m_rowData[row];
    bool dark = isDarkTheme();

    /* All IP-mode protocols with their port applicability */
    struct ProtoEntry {
        int     id;
        QString name;
        QString hint;      /* "(port N)" shown only for non-applicable entries */
        bool    applicable;
    };

    QList<ProtoEntry> protocols = {
        {  1, "TLS Information",            "(port 443)",
           (rd.isTcp || rd.isUdp) && rd.port == 443 },
        {  2, "HTTP Information",           "(port 80)",
           rd.isTcp && rd.port == 80 },
        {  3, "SMB / DCE-RPC Information",  "(port 445/135)",
           rd.isTcp && (rd.port == 445 || rd.port == 135) },
        {  4, "Kerberos Information",       "(port 88)",
           (rd.isTcp || rd.isUdp) && rd.port == 88 },
        {  5, "Email Protocol Information", "(SMTP/IMAP/POP3)",
           rd.isTcp && (rd.port == 25 || rd.port == 587 || rd.port == 465 ||
                        rd.port == 143 || rd.port == 993 ||
                        rd.port == 110 || rd.port == 995) },
        {  6, "SQL Database Information",   "(port 1433/3306/5432)",
           rd.isTcp && (rd.port == 1433 || rd.port == 3306 || rd.port == 5432) },
        {  7, "VoIP / SIP Information",     "(port 5060/5061)",
           (rd.isTcp || rd.isUdp) && (rd.port == 5060 || rd.port == 5061) },
        {  8, "DHCP Information",           "(port 67/68 UDP)",
           rd.isUdp && (rd.port == 67 || rd.port == 68) },
        {  9, "DNS Information",            "(port 53)",
           (rd.isUdp || rd.isTcp) && rd.port == 53 },
        { 10, "LDAP Information",           "(port 389/636/3268/3269)",
           rd.isTcp && (rd.port == 389 || rd.port == 636 ||
                        rd.port == 3268 || rd.port == 3269) },
        { 11, "SNMP Information",           "(port 161/162)",
           (rd.isUdp || rd.isTcp) && (rd.port == 161 || rd.port == 162) },
        { 12, "Syslog Information",         "(port 514/601/6514)",
           (rd.isUdp || rd.isTcp) &&
           (rd.port == 514 || rd.port == 601 || rd.port == 6514) },
        { 13, "SSH / SFTP / SCP Information","(port 22)",
           rd.isTcp && rd.port == 22 },
        { 14, "FTP Information",            "(port 21/20/990)",
           rd.isTcp && (rd.port == 21 || rd.port == 20 || rd.port == 990) },
        { 15, "Telnet Information",         "(port 23/992)",
           rd.isTcp && (rd.port == 23 || rd.port == 992) },
        { 16, "NBNS Information",           "(port 137 UDP)",
           rd.isUdp && rd.port == 137 },
        { 17, "NetBIOS Datagram Information","(port 138 UDP)",
           rd.isUdp && rd.port == 138 },
        { 18, "NetBIOS Session Information", "(port 139 TCP)",
           rd.isTcp && rd.port == 139 },
    };

    /* Build the dialog */
    QDialog browser(nullptr);   /* not parented &mdash; same safety pattern as QMenu */
    browser.setWindowTitle("Supported Protocols");
    browser.resize(420, 480);

    QVBoxLayout *mainLayout = new QVBoxLayout(&browser);
    mainLayout->setSpacing(8);
    mainLayout->setContentsMargins(14, 12, 14, 12);

    /* Intro text explaining the purpose of this dialog */
    QLabel *introLbl = new QLabel(
        "<b>PacketCircle Protocol Analyses</b><br>"
        "<span style='color:#888; font-size:11px;'>"
        "Right-click any connection row to open the analysis directly.<br>"
        "Protocols matching the selected port are shown in <b>bold</b>.</span>",
        &browser);
    introLbl->setTextFormat(Qt::RichText);
    introLbl->setWordWrap(true);
    mainLayout->addWidget(introLbl);

    /* Connection header */
    QString src = QString::fromUtf8(m_pair->src_addr);
    QString dst = QString::fromUtf8(m_pair->dst_addr);
    QLabel *headerLbl = new QLabel(
        QString("Connection: <b>%1</b> &nbsp;&#8596;&nbsp; <b>%2</b>"
                "&nbsp;&nbsp;&mdash;&nbsp;&nbsp;port&nbsp;<b>%3</b>")
            .arg(src.toHtmlEscaped(), dst.toHtmlEscaped(), QString::number(rd.port)),
        &browser);
    headerLbl->setTextFormat(Qt::RichText);
    mainLayout->addWidget(headerLbl);

    /* ── INFO note ─────────────────────────────────────────────────── */
    QColor noteBg   = dark ? QColor(0x1a, 0x2a, 0x3a) : QColor(0xe8, 0xf4, 0xff);
    QColor noteFg   = dark ? QColor(0x8a, 0xc8, 0xf0) : QColor(0x1a, 0x5a, 0x9a);
    QLabel *infoLbl = new QLabel(
        "<b>INFO:</b>  Right-click any connection row with a matching protocol "
        "to open its analysis directly from the context menu.<br>"
        "Protocols matching the current port are shown in <b>bold</b> below.",
        &browser);
    infoLbl->setTextFormat(Qt::RichText);
    infoLbl->setWordWrap(true);
    infoLbl->setContentsMargins(10, 7, 10, 7);
    QPalette infoPal = infoLbl->palette();
    infoPal.setColor(QPalette::Window,     noteBg);
    infoPal.setColor(QPalette::WindowText, noteFg);
    infoLbl->setPalette(infoPal);
    infoLbl->setAutoFillBackground(true);
    mainLayout->addWidget(infoLbl);

    /* ── Protocol list — read-only reference, no selection ─────────── */
    QListWidget *list = new QListWidget(&browser);
    list->setSelectionMode(QAbstractItemView::NoSelection);
    list->setFocusPolicy(Qt::NoFocus);
    list->setAlternatingRowColors(false);

    QColor applicableColor = dark ? QColor(0xe8, 0xe8, 0xe8) : QColor(0x1a, 0x1a, 0x1a);
    QColor otherColor      = dark ? QColor(0xaa, 0xaa, 0xaa) : QColor(0x55, 0x55, 0x55);
    QColor sepColor        = dark ? QColor(0x77, 0x77, 0x88) : QColor(0x88, 0x88, 0x99);

    /* Applicable protocols first — bold, clearly readable */
    bool hasApplicable = false;
    for (const auto &p : protocols) {
        if (!p.applicable) continue;
        QListWidgetItem *item = new QListWidgetItem(p.name + "  " + p.hint, list);
        item->setFlags(Qt::ItemIsEnabled);
        QFont f = item->font();
        f.setBold(true);
        f.setPointSize(f.pointSize() + 1);
        item->setFont(f);
        item->setForeground(applicableColor);
        hasApplicable = true;
    }

    /* Visual separator */
    if (hasApplicable) {
        QListWidgetItem *sep = new QListWidgetItem(
            "\u2500\u2500\u2500  All supported protocols  \u2500\u2500\u2500", list);
        sep->setFlags(Qt::ItemIsEnabled);
        sep->setForeground(sepColor);
        QFont sf = sep->font();
        sf.setItalic(true);
        sep->setFont(sf);
    }

    /* All protocols (applicable already shown above — skip them here,
     * list everything so the full catalogue is always visible) */
    for (const auto &p : protocols) {
        QListWidgetItem *item = new QListWidgetItem(
            p.name + "  " + p.hint, list);
        item->setFlags(Qt::ItemIsEnabled);
        QFont f = item->font();
        if (p.applicable) f.setBold(true);
        item->setFont(f);
        item->setForeground(p.applicable ? applicableColor : otherColor);
    }

    mainLayout->addWidget(list, 1);

    /* Dark theme stylesheet */
    if (dark) {
        browser.setStyleSheet(
            "QDialog { background:#1e1e1e; color:#e0e0e0; }"
            "QLabel  { color:#e0e0e0; }"
            "QListWidget {"
            "  background:#2b2b2b; border:1px solid #444;"
            "  outline:0;"
            "}"
            "QListWidget::item { padding:3px 6px; }"
            "QListWidget::item:hover { background:#333; }"
            "QPushButton {"
            "  background:#333; color:#e0e0e0; border:1px solid #555;"
            "  padding:4px 16px; border-radius:3px;"
            "}"
            "QPushButton:hover { background:#444; }"
        );
    }

    /* Close button only — details are accessed via right-click, not here */
    QHBoxLayout *btnRow = new QHBoxLayout;
    btnRow->addStretch(1);
    QPushButton *closeBtn = new QPushButton("Close", &browser);
    btnRow->addWidget(closeBtn);
    mainLayout->addLayout(btnRow);

    QObject::connect(closeBtn, &QPushButton::clicked, &browser, &QDialog::reject);

    /* Stop auto-close while browser is open */
    m_contextMenuActive = true;
    if (m_autoCloseTimer) m_autoCloseTimer->stop();

    browser.exec();

    /* Always resume auto-close after closing — no dispatch from this dialog */
    m_contextMenuActive = false;
    if (m_autoCloseTimer) m_autoCloseTimer->start();
}

QString ConnectionPopup::buildFilterForRow(int row)
{
    if (row < 0 || row >= m_rowData.size() || !m_pair)
        return QString();

    const RowData &rd = m_rowData[row];
    
    /* Always use raw addresses for filter construction.
     * extractRawMAC() strips resolved names like "Cisco_a9:38:40 (00:1b:2b:...)" */
    QString src = extractRawMAC(QString::fromUtf8(m_pair->src_addr));
    QString dst = extractRawMAC(QString::fromUtf8(m_pair->dst_addr));

    /* Detect address type from format rather than trusting m_useMAC flag.
     * MAC addresses look like xx:xx:xx:xx:xx:xx (6 colon-separated groups).
     * This prevents using eth.addr with IP addresses or vice versa.        */
    bool looksLikeMAC = (src.count(':') == 5 && dst.count(':') == 5);

    /* Build address clause using bidirectional matching */
    QString addrFilter;
    if (looksLikeMAC) {
        addrFilter = QString("eth.addr == %1 && eth.addr == %2").arg(src).arg(dst);
    } else {
        addrFilter = QString("ip.addr == %1 && ip.addr == %2").arg(src).arg(dst);
    }

    /* Build port clause using per-port protocol info for accuracy.
     * When both TCP and UDP were observed on the same port, include both. */
    QString portFilter;
    if (rd.isTcp && rd.isUdp) {
        portFilter = QString("(tcp.port == %1 || udp.port == %1)").arg(rd.port);
    } else if (rd.isTcp) {
        portFilter = QString("tcp.port == %1").arg(rd.port);
    } else if (rd.isUdp) {
        portFilter = QString("udp.port == %1").arg(rd.port);
    } else {
        /* Unknown transport — just filter by addresses */
        return QString("(%1)").arg(addrFilter);
    }

    return QString("(%1 && %2)").arg(addrFilter).arg(portFilter);
}

void ConnectionPopup::applyFilterForRow(int row)
{
    QString filter = buildFilterForRow(row);
    if (filter.isEmpty())
        return;

    QByteArray filterBytes = filter.toUtf8();
    QPointer<ConnectionPopup> guard(this);
    plugin_if_apply_filter(filterBytes.constData(), true);
    if (!guard) return;   /* destroyed during event-loop re-entry */
    hide();
    deleteLater();
}

void ConnectionPopup::followTCPStreamForRow(int row)
{
    if (row < 0 || row >= m_rowData.size() || !m_pair)
        return;

    const RowData &rd = m_rowData[row];
    if (!rd.isTcp)
        return;

    /* Step 1: Apply a narrowing filter so Wireshark selects the right TCP
     * conversation.  This ensures the "current packet" belongs to the
     * desired stream when we subsequently trigger Follow TCP Stream.       */
    QString filter = buildFilterForRow(row);
    if (filter.isEmpty()) return;
    QByteArray filterBytes = filter.toUtf8();
    QPointer<ConnectionPopup> guard(this);
    plugin_if_apply_filter(filterBytes.constData(), true);

    /* Step 2: After a brief delay (letting the filter take effect and
     * Wireshark select the first matching packet), programmatically trigger
     * the "Follow TCP Stream" menu action inside Wireshark's main window.  */
    QTimer::singleShot(400, qApp, []() {
        for (QWidget *w : QApplication::topLevelWidgets()) {
            QMainWindow *mainWin = qobject_cast<QMainWindow *>(w);
            if (!mainWin || !mainWin->menuBar()) continue;

            /* Walk the menu bar: look for a "Follow" submenu (under Analyze) */
            for (QAction *topAction : mainWin->menuBar()->actions()) {
                QMenu *topMenu = topAction->menu();
                if (!topMenu) continue;

                for (QAction *midAction : topMenu->actions()) {
                    QMenu *subMenu = midAction->menu();
                    if (!subMenu) continue;
                    if (!subMenu->title().contains("Follow", Qt::CaseInsensitive))
                        continue;

                    /* Found the "Follow" submenu — look for TCP Stream */
                    for (QAction *followAction : subMenu->actions()) {
                        if (followAction->text().contains("TCP Stream", Qt::CaseInsensitive) &&
                            followAction->isEnabled()) {
                            followAction->trigger();
                            return;
                        }
                    }
                }
            }
        }
    });

    if (!guard) return;   /* destroyed during event-loop re-entry */
    hide();
    deleteLater();
}

void ConnectionPopup::openTcpStreamGraph(int row, const QString &graphName)
{
    if (row < 0 || row >= m_rowData.size() || !m_pair)
        return;

    const RowData &rd = m_rowData[row];
    if (!rd.isTcp)
        return;

    /* Step 1: Apply a narrowing filter so Wireshark selects a packet from
     * the desired TCP stream.                                              */
    QString filter = buildFilterForRow(row);
    if (filter.isEmpty()) return;
    QByteArray filterBytes = filter.toUtf8();
    QPointer<ConnectionPopup> guard(this);
    plugin_if_apply_filter(filterBytes.constData(), true);

    /* Step 2: After a brief delay, walk Wireshark's menu bar to find
     * Statistics → TCP Stream Graphs → <graphName> and trigger it.         */
    QString target = graphName;
    QTimer::singleShot(400, qApp, [target]() {
        for (QWidget *w : QApplication::topLevelWidgets()) {
            QMainWindow *mainWin = qobject_cast<QMainWindow *>(w);
            if (!mainWin || !mainWin->menuBar()) continue;

            for (QAction *topAction : mainWin->menuBar()->actions()) {
                QMenu *topMenu = topAction->menu();
                if (!topMenu) continue;

                /* Look for the "TCP Stream Graphs" submenu */
                for (QAction *midAction : topMenu->actions()) {
                    QMenu *subMenu = midAction->menu();
                    if (!subMenu) continue;
                    if (!subMenu->title().contains("TCP Stream Graphs", Qt::CaseInsensitive))
                        continue;

                    /* Found — look for the specific graph action */
                    for (QAction *graphAction : subMenu->actions()) {
                        if (graphAction->text().contains(target, Qt::CaseInsensitive) &&
                            graphAction->isEnabled()) {
                            graphAction->trigger();
                            return;
                        }
                    }
                }
            }
        }
    });

    if (!guard) return;   /* destroyed during event-loop re-entry */
    hide();
    deleteLater();
}

/* ------------------------------------------------------------------ */
/* Custom widget that draws a sorry smiley face                       */
/* ------------------------------------------------------------------ */
class SorrySmileyWidget : public QWidget
{
public:
    explicit SorrySmileyWidget(QWidget *parent = nullptr) : QWidget(parent) {
        setMinimumSize(120, 120);
        setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
    }
protected:
    void paintEvent(QPaintEvent *) override {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing);
        int sz = qMin(width(), height());
        int cx = width() / 2, cy = height() / 2;
        int r = sz / 2 - 4;

        /* Face circle */
        p.setPen(QPen(QColor("#c0930a"), 3));
        p.setBrush(QColor("#fdd835"));
        p.drawEllipse(QPoint(cx, cy), r, r);

        /* Eyes — slightly sad, looking down */
        int eyeY = cy - r / 4;
        int eyeSpacing = r / 3;
        p.setPen(Qt::NoPen);
        p.setBrush(QColor("#5d4037"));
        p.drawEllipse(QPoint(cx - eyeSpacing, eyeY), r / 8, r / 6);
        p.drawEllipse(QPoint(cx + eyeSpacing, eyeY), r / 8, r / 6);

        /* Frown — arc curving upward (sad mouth) */
        p.setPen(QPen(QColor("#5d4037"), 3, Qt::SolidLine, Qt::RoundCap));
        p.setBrush(Qt::NoBrush);
        QRect mouthRect(cx - r / 3, cy + r / 6, r * 2 / 3, r / 2);
        p.drawArc(mouthRect, 20 * 16, 140 * 16);
    }
};

/* ------------------------------------------------------------------ */
/* TLS Information dialog                                             */
/* ------------------------------------------------------------------ */
void ConnectionPopup::showTlsInfoForRow(int row)
{
    if (row < 0 || row >= m_rowData.size() || !m_pair)
        return;

    /* Obtain the current capture file from Wireshark */
    capture_file *cf = (capture_file *)plugin_if_get_capture_file(
        extract_capture_file, NULL);

    if (!cf) {
        QMessageBox::warning(this, "TLS Information",
            "No capture file is currently loaded in Wireshark.");
        return;
    }

    /* Determine addresses for the analysis */
    QString src = QString::fromUtf8(m_pair->src_addr);
    QString dst = QString::fromUtf8(m_pair->dst_addr);
    bool looksLikeMAC = (src.count(':') == 5 && dst.count(':') == 5);
    const RowData &rd = m_rowData[row];

    /* Run the TLS analysis */
    tls_info_t *tls = packet_analyzer_extract_tls_info(
        cf,
        m_pair->src_addr,
        m_pair->dst_addr,
        rd.port,
        looksLikeMAC ? TRUE : FALSE);

    /* Build the dialog */
    bool dark = isDarkTheme();
    QDialog *dlg = new QDialog(nullptr);
    dlg->setWindowTitle("TLS Information");
    dlg->setAttribute(Qt::WA_DeleteOnClose);
    dlg->setMinimumSize(520, 400);
    dlg->resize(620, 520);
    dlg->setSizeGripEnabled(true);

    QVBoxLayout *mainLayout = new QVBoxLayout(dlg);
    mainLayout->setContentsMargins(16, 16, 16, 16);
    mainLayout->setSpacing(12);

    if (!tls || !tls->found) {
        /* ---- No TLS data: show sorry smiley ---- */
        mainLayout->addStretch(1);

        SorrySmileyWidget *smiley = new SorrySmileyWidget(dlg);
        smiley->setFixedSize(140, 140);
        QHBoxLayout *smileyRow = new QHBoxLayout;
        smileyRow->addStretch(1);
        smileyRow->addWidget(smiley);
        smileyRow->addStretch(1);
        mainLayout->addLayout(smileyRow);

        QLabel *sorryLabel = new QLabel(
            "Sorry, no TLS Handshakes in the buffer", dlg);
        sorryLabel->setAlignment(Qt::AlignCenter);
        sorryLabel->setStyleSheet(
            QString("font-size: 16px; font-weight: bold; color: %1; padding: 12px;")
                .arg(dark ? "#e0e0e0" : "#333"));
        mainLayout->addWidget(sorryLabel);

        /* Diagnostic detail so the user (or developer) can see what was tried */
        QString addrField = looksLikeMAC ? "eth.addr" : "ip.addr";
        QString filterUsed = QString("%1 == %2 && %1 == %3 && tcp.port == %4")
            .arg(addrField).arg(src).arg(dst).arg(rd.port);
        QString diagText = QString(
            "<div style='text-align:center; color:%1; font-size:12px; padding:8px;'>"
            "Filter: <span style='font-family:monospace;'>%2</span><br>"
            "Packets matched: <b>%3</b> &nbsp;|&nbsp; "
            "Handshake messages: <b>%4</b>"
            "</div>")
            .arg(dark ? "#888" : "#999")
            .arg(filterUsed.toHtmlEscaped())
            .arg(tls ? tls->matched_packets : 0)
            .arg(tls ? tls->handshake_count : 0);
        QLabel *diagLabel = new QLabel(diagText, dlg);
        diagLabel->setAlignment(Qt::AlignCenter);
        diagLabel->setTextFormat(Qt::RichText);
        mainLayout->addWidget(diagLabel);

        mainLayout->addStretch(1);
    } else {
        /* ---- Build rich HTML content ---- */
        QString html;
        QString headingColor = dark ? "#90caf9" : "#1565c0";
        QString textColor    = dark ? "#e0e0e0" : "#222";
        QString dimColor     = dark ? "#999"    : "#666";
        QString valColor     = dark ? "#c8e6c9" : "#1b5e20";

        html += QString("<div style='color:%1;'>").arg(textColor);

        /* Connection header */
        html += QString("<h3 style='color:%1; margin-bottom:4px;'>Connection</h3>").arg(headingColor);
        html += QString("<table cellpadding='3'>"
                        "<tr><td style='color:%1;'>Endpoints:</td>"
                        "<td><b>%2</b> &#8596; <b>%3</b></td></tr>"
                        "<tr><td style='color:%1;'>Port:</td>"
                        "<td><b>%4</b></td></tr>"
                        "<tr><td style='color:%1;'>Handshake packets:</td>"
                        "<td><b>%5</b></td></tr>"
                        "</table><br>")
                    .arg(dimColor)
                    .arg(src.toHtmlEscaped())
                    .arg(dst.toHtmlEscaped())
                    .arg(rd.port)
                    .arg(tls->handshake_count);

        /* TLS Handshake info */
        html += QString("<h3 style='color:%1; margin-bottom:4px;'>TLS Handshake</h3>").arg(headingColor);
        html += "<table cellpadding='3'>";
        if (tls->sni) {
            html += QString("<tr><td style='color:%1;'>Server Name (SNI):</td>"
                            "<td style='color:%2;'><b>%3</b></td></tr>")
                        .arg(dimColor).arg(valColor)
                        .arg(QString::fromUtf8(tls->sni).toHtmlEscaped());
        }
        if (tls->version) {
            html += QString("<tr><td style='color:%1;'>Version:</td>"
                            "<td><b>%2</b></td></tr>")
                        .arg(dimColor)
                        .arg(QString::fromUtf8(tls->version).toHtmlEscaped());
        }
        if (tls->cipher_suite) {
            html += QString("<tr><td style='color:%1;'>Cipher Suite:</td>"
                            "<td><b>%2</b></td></tr>")
                        .arg(dimColor)
                        .arg(QString::fromUtf8(tls->cipher_suite).toHtmlEscaped());
        }
        if (tls->alpn) {
            html += QString("<tr><td style='color:%1;'>ALPN:</td>"
                            "<td><b>%2</b></td></tr>")
                        .arg(dimColor)
                        .arg(QString::fromUtf8(tls->alpn).toHtmlEscaped());
        }
        if (tls->sig_algorithm) {
            html += QString("<tr><td style='color:%1;'>Signature Algorithm:</td>"
                            "<td><b>%2</b></td></tr>")
                        .arg(dimColor)
                        .arg(QString::fromUtf8(tls->sig_algorithm).toHtmlEscaped());
        }
        html += "</table><br>";

        /* Fingerprints (JA4 / JA4S) — only shown when available */
        if (tls->ja4 || tls->ja4s) {
            html += QString("<h3 style='color:%1; margin-bottom:4px;'>Fingerprints</h3>").arg(headingColor);
            html += "<table cellpadding='3'>";
            if (tls->ja4) {
                html += QString("<tr><td style='color:%1;'>JA4 (Client):</td>"
                                "<td style='font-family:monospace;'><b>%2</b></td></tr>")
                            .arg(dimColor)
                            .arg(QString::fromUtf8(tls->ja4).toHtmlEscaped());
            }
            if (tls->ja4s) {
                html += QString("<tr><td style='color:%1;'>JA4S (Server):</td>"
                                "<td style='font-family:monospace;'><b>%2</b></td></tr>")
                            .arg(dimColor)
                            .arg(QString::fromUtf8(tls->ja4s).toHtmlEscaped());
            }
            html += "</table><br>";
        }

        /* Certificates */
        if (tls->certificates) {
            html += QString("<h3 style='color:%1; margin-bottom:4px;'>Certificates</h3>").arg(headingColor);
            int certNum = 0;
            for (GList *cl = tls->certificates; cl; cl = cl->next) {
                tls_cert_info_t *cert = (tls_cert_info_t *)cl->data;
                certNum++;
                if (!cert) continue;

                QString certLabel = (certNum == 1) ? "Server Certificate"
                    : QString("Certificate #%1 (CA / Intermediate)").arg(certNum);
                html += QString("<h4 style='color:%1; margin:6px 0 2px 0;'>%2</h4>")
                            .arg(headingColor).arg(certLabel);
                html += "<table cellpadding='3'>";

                if (cert->subject_cn) {
                    html += QString("<tr><td style='color:%1;'>Subject CN:</td>"
                                    "<td style='color:%2;'><b>%3</b></td></tr>")
                                .arg(dimColor).arg(valColor)
                                .arg(QString::fromUtf8(cert->subject_cn).toHtmlEscaped());
                }
                if (cert->issuer_cn) {
                    html += QString("<tr><td style='color:%1;'>Issuer:</td>"
                                    "<td><b>%2</b></td></tr>")
                                .arg(dimColor)
                                .arg(QString::fromUtf8(cert->issuer_cn).toHtmlEscaped());
                }
                if (cert->serial_number) {
                    html += QString("<tr><td style='color:%1;'>Serial Number:</td>"
                                    "<td style='font-family:monospace;'>%2</td></tr>")
                                .arg(dimColor)
                                .arg(QString::fromUtf8(cert->serial_number).toHtmlEscaped());
                }
                if (cert->not_before) {
                    html += QString("<tr><td style='color:%1;'>Valid From:</td>"
                                    "<td><b>%2</b></td></tr>")
                                .arg(dimColor)
                                .arg(QString::fromUtf8(cert->not_before).toHtmlEscaped());
                }
                if (cert->not_after) {
                    html += QString("<tr><td style='color:%1;'>Valid Until:</td>"
                                    "<td><b>%2</b></td></tr>")
                                .arg(dimColor)
                                .arg(QString::fromUtf8(cert->not_after).toHtmlEscaped());
                }
                html += "</table>";

                /* SAN DNS names */
                if (cert->san_dns_names) {
                    html += QString("<div style='margin:4px 0 0 8px;'>"
                                    "<span style='color:%1;'>Subject Alternative Names:</span><br>")
                                .arg(dimColor);
                    for (GList *sl = cert->san_dns_names; sl; sl = sl->next) {
                        const gchar *dns = (const gchar *)sl->data;
                        if (dns) {
                            html += QString("&nbsp;&nbsp;&#8226; <b>%1</b><br>")
                                        .arg(QString::fromUtf8(dns).toHtmlEscaped());
                        }
                    }
                    html += "</div>";
                }
            }
        }

        html += "</div>";

        QTextEdit *textEdit = new QTextEdit(dlg);
        textEdit->setReadOnly(true);
        textEdit->setHtml(html);
        if (dark) {
            textEdit->setStyleSheet(
                "QTextEdit {"
                "  background: #1e1e1e;"
                "  color: #e0e0e0;"
                "  border: 1px solid #444;"
                "  border-radius: 4px;"
                "  padding: 8px;"
                "}");
        } else {
            textEdit->setStyleSheet(
                "QTextEdit {"
                "  background: #fafafa;"
                "  color: #222;"
                "  border: 1px solid #ccc;"
                "  border-radius: 4px;"
                "  padding: 8px;"
                "}");
        }
        mainLayout->addWidget(textEdit);
    }

    /* Close button */
    QHBoxLayout *btnRow = new QHBoxLayout;
    btnRow->addStretch(1);
    QPushButton *closeBtn = new QPushButton("Close", dlg);
    closeBtn->setFixedWidth(100);
    if (dark) {
        closeBtn->setStyleSheet(
            "QPushButton {"
            "  background: #444; color: #e0e0e0; border: 1px solid #666;"
            "  border-radius: 4px; padding: 6px 16px; font-weight: bold;"
            "}"
            "QPushButton:hover { background: #555; }");
    } else {
        closeBtn->setStyleSheet(
            "QPushButton {"
            "  background: #e0e0e0; color: #222; border: 1px solid #aaa;"
            "  border-radius: 4px; padding: 6px 16px; font-weight: bold;"
            "}"
            "QPushButton:hover { background: #d0d0d0; }");
    }
    QObject::connect(closeBtn, &QPushButton::clicked, dlg, &QDialog::accept);
    btnRow->addWidget(closeBtn);
    btnRow->addStretch(1);
    mainLayout->addLayout(btnRow);

    /* Clean up TLS info after dialog closes */
    packet_analyzer_free_tls_info(tls);

    /* Close the popup first, then show the dialog */
    /* Stop auto-close timer while dialog is open. deleteLater() AFTER exec()
     * ensures the object is not freed during the dialog's nested event loop
     * (would cause SIGSEGV if the timer also fires deleteLater mid-exec).   */
    if (m_autoCloseTimer) m_autoCloseTimer->stop();
    m_contextMenuActive = true;
    hide();
    dlg->exec();
    deleteLater();
}

/* ------------------------------------------------------------------ */
/* HTTP Information dialog                                             */
/* ------------------------------------------------------------------ */
void ConnectionPopup::showHttpInfoForRow(int row)
{
    if (row < 0 || row >= m_rowData.size() || !m_pair)
        return;

    capture_file *cf = (capture_file *)plugin_if_get_capture_file(
        extract_capture_file, NULL);

    if (!cf) {
        QMessageBox::warning(this, "HTTP Information",
            "No capture file is currently loaded in Wireshark.");
        return;
    }

    QString src = QString::fromUtf8(m_pair->src_addr);
    QString dst = QString::fromUtf8(m_pair->dst_addr);
    bool looksLikeMAC = (src.count(':') == 5 && dst.count(':') == 5);
    const RowData &rd = m_rowData[row];

    http_info_t *http = packet_analyzer_extract_http_info(
        cf,
        m_pair->src_addr,
        m_pair->dst_addr,
        rd.port,
        looksLikeMAC ? TRUE : FALSE);

    bool dark = isDarkTheme();
    QDialog *dlg = new QDialog(nullptr);
    dlg->setWindowTitle("HTTP Information");
    dlg->setAttribute(Qt::WA_DeleteOnClose);
    dlg->setMinimumSize(560, 420);
    dlg->resize(680, 560);
    dlg->setSizeGripEnabled(true);

    QVBoxLayout *mainLayout = new QVBoxLayout(dlg);
    mainLayout->setContentsMargins(16, 16, 16, 16);
    mainLayout->setSpacing(12);

    if (!http || !http->found) {
        /* ---- No HTTP data: show sorry smiley ---- */
        mainLayout->addStretch(1);

        SorrySmileyWidget *smiley = new SorrySmileyWidget(dlg);
        smiley->setFixedSize(140, 140);
        QHBoxLayout *smileyRow = new QHBoxLayout;
        smileyRow->addStretch(1);
        smileyRow->addWidget(smiley);
        smileyRow->addStretch(1);
        mainLayout->addLayout(smileyRow);

        QLabel *sorryLabel = new QLabel(
            "Sorry, no HTTP traffic found in the buffer", dlg);
        sorryLabel->setAlignment(Qt::AlignCenter);
        sorryLabel->setStyleSheet(
            QString("font-size: 16px; font-weight: bold; color: %1; padding: 12px;")
                .arg(dark ? "#e0e0e0" : "#333"));
        mainLayout->addWidget(sorryLabel);

        QString diagText = QString(
            "<div style='text-align:center; color:%1; font-size:12px; padding:8px;'>"
            "Packets matched: <b>%2</b> &nbsp;|&nbsp; "
            "Requests: <b>%3</b> &nbsp;|&nbsp; Responses: <b>%4</b>"
            "</div>")
            .arg(dark ? "#888" : "#999")
            .arg(http ? http->matched_packets : 0)
            .arg(http ? http->request_count : 0)
            .arg(http ? http->response_count : 0);
        QLabel *diagLabel = new QLabel(diagText, dlg);
        diagLabel->setAlignment(Qt::AlignCenter);
        diagLabel->setTextFormat(Qt::RichText);
        mainLayout->addWidget(diagLabel);

        mainLayout->addStretch(1);
    } else {
        /* ---- Build rich HTML content ---- */
        QString html;
        QString headingColor = dark ? "#90caf9" : "#1565c0";
        QString textColor    = dark ? "#e0e0e0" : "#222";
        QString dimColor     = dark ? "#999"    : "#666";
        QString valColor     = dark ? "#c8e6c9" : "#1b5e20";

        html += QString("<div style='color:%1;'>").arg(textColor);

        /* Connection header */
        html += QString("<h3 style='color:%1; margin-bottom:4px;'>Connection</h3>").arg(headingColor);
        html += QString("<table cellpadding='3'>"
                        "<tr><td style='color:%1;'>Endpoints:</td>"
                        "<td><b>%2</b> &#8596; <b>%3</b></td></tr>"
                        "<tr><td style='color:%1;'>Port:</td>"
                        "<td><b>%4</b></td></tr>"
                        "<tr><td style='color:%1;'>Packets matched:</td>"
                        "<td><b>%5</b></td></tr>"
                        "<tr><td style='color:%1;'>Requests / Responses:</td>"
                        "<td><b>%6</b> / <b>%7</b></td></tr>"
                        "</table><br>")
                    .arg(dimColor)
                    .arg(src.toHtmlEscaped())
                    .arg(dst.toHtmlEscaped())
                    .arg(rd.port)
                    .arg(http->matched_packets)
                    .arg(http->request_count)
                    .arg(http->response_count);

        /* Hosts */
        if (http->hosts) {
            html += QString("<h3 style='color:%1; margin-bottom:4px;'>Host(s)</h3>").arg(headingColor);
            for (GList *l = http->hosts; l; l = l->next) {
                const gchar *h = (const gchar *)l->data;
                if (h) html += QString("&nbsp;&nbsp;&#8226; <b style='color:%1;'>%2</b><br>")
                                   .arg(valColor).arg(QString::fromUtf8(h).toHtmlEscaped());
            }
            html += "<br>";
        }

        /* User-Agents */
        if (http->user_agents) {
            html += QString("<h3 style='color:%1; margin-bottom:4px;'>User-Agent(s)</h3>").arg(headingColor);
            for (GList *l = http->user_agents; l; l = l->next) {
                const gchar *ua = (const gchar *)l->data;
                if (ua) html += QString("&nbsp;&nbsp;&#8226; %1<br>")
                                    .arg(QString::fromUtf8(ua).toHtmlEscaped());
            }
            html += "<br>";
        }

        /* Servers */
        if (http->servers) {
            html += QString("<h3 style='color:%1; margin-bottom:4px;'>Server(s)</h3>").arg(headingColor);
            for (GList *l = http->servers; l; l = l->next) {
                const gchar *sv = (const gchar *)l->data;
                if (sv) html += QString("&nbsp;&nbsp;&#8226; <b>%1</b><br>")
                                    .arg(QString::fromUtf8(sv).toHtmlEscaped());
            }
            html += "<br>";
        }

        /* Response Codes */
        if (http->status_codes && g_hash_table_size(http->status_codes) > 0) {
            html += QString("<h3 style='color:%1; margin-bottom:4px;'>Response Status Codes</h3>").arg(headingColor);
            html += "<table cellpadding='3'>";
            GHashTableIter iter;
            gpointer key, value;
            g_hash_table_iter_init(&iter, http->status_codes);
            while (g_hash_table_iter_next(&iter, &key, &value)) {
                const gchar *code = (const gchar *)key;
                guint count = GPOINTER_TO_UINT(value);
                /* Color-code: 2xx green, 3xx blue, 4xx orange, 5xx red */
                QString codeColor = valColor;
                if (code && code[0] == '3') codeColor = dark ? "#90caf9" : "#1565c0";
                else if (code && code[0] == '4') codeColor = dark ? "#ffcc80" : "#e65100";
                else if (code && code[0] == '5') codeColor = dark ? "#ef9a9a" : "#b71c1c";
                html += QString("<tr><td style='color:%1; font-weight:bold; font-size:14px;'>%2</td>"
                                "<td style='color:%3;'>&#215; %4</td></tr>")
                            .arg(codeColor)
                            .arg(QString::fromUtf8(code).toHtmlEscaped())
                            .arg(dimColor)
                            .arg(count);
            }
            html += "</table><br>";
        }

        /* Content-Types */
        if (http->content_types) {
            html += QString("<h3 style='color:%1; margin-bottom:4px;'>Content Types</h3>").arg(headingColor);
            for (GList *l = http->content_types; l; l = l->next) {
                const gchar *ct = (const gchar *)l->data;
                if (ct) html += QString("&nbsp;&nbsp;&#8226; <span style='font-family:monospace;'>%1</span><br>")
                                    .arg(QString::fromUtf8(ct).toHtmlEscaped());
            }
            html += "<br>";
        }

        /* Requests */
        if (http->requests) {
            html += QString("<h3 style='color:%1; margin-bottom:4px;'>Requests (%2)</h3>")
                        .arg(headingColor).arg(http->request_count);
            html += "<table cellpadding='2' style='font-size:12px;'>";
            int reqNum = 0;
            for (GList *l = http->requests; l; l = l->next) {
                http_request_entry_t *req = (http_request_entry_t *)l->data;
                if (!req) continue;
                reqNum++;
                if (reqNum > 50) {
                    html += QString("<tr><td colspan='3' style='color:%1;'>"
                                    "... and %2 more requests</td></tr>")
                                .arg(dimColor).arg(http->request_count - 50);
                    break;
                }
                html += QString("<tr>"
                                "<td style='color:%1; font-weight:bold;'>%2</td>"
                                "<td style='font-family:monospace;'>%3</td>"
                                "<td style='color:%4;'>%5</td>"
                                "</tr>")
                            .arg(valColor)
                            .arg(req->method ? QString::fromUtf8(req->method).toHtmlEscaped() : "")
                            .arg(req->uri ? QString::fromUtf8(req->uri).toHtmlEscaped() : "")
                            .arg(dimColor)
                            .arg(req->host ? QString::fromUtf8(req->host).toHtmlEscaped() : "");
            }
            html += "</table>";
        }

        html += "</div>";

        QTextEdit *textEdit = new QTextEdit(dlg);
        textEdit->setReadOnly(true);
        textEdit->setHtml(html);
        if (dark) {
            textEdit->setStyleSheet(
                "QTextEdit {"
                "  background: #1e1e1e;"
                "  color: #e0e0e0;"
                "  border: 1px solid #444;"
                "  border-radius: 4px;"
                "  padding: 8px;"
                "}");
        } else {
            textEdit->setStyleSheet(
                "QTextEdit {"
                "  background: #fafafa;"
                "  color: #222;"
                "  border: 1px solid #ccc;"
                "  border-radius: 4px;"
                "  padding: 8px;"
                "}");
        }
        mainLayout->addWidget(textEdit);
    }

    /* Close button */
    QHBoxLayout *btnRow = new QHBoxLayout;
    btnRow->addStretch(1);
    QPushButton *closeBtn = new QPushButton("Close", dlg);
    closeBtn->setFixedWidth(100);
    if (dark) {
        closeBtn->setStyleSheet(
            "QPushButton {"
            "  background: #444; color: #e0e0e0; border: 1px solid #666;"
            "  border-radius: 4px; padding: 6px 16px; font-weight: bold;"
            "}"
            "QPushButton:hover { background: #555; }");
    } else {
        closeBtn->setStyleSheet(
            "QPushButton {"
            "  background: #e0e0e0; color: #222; border: 1px solid #aaa;"
            "  border-radius: 4px; padding: 6px 16px; font-weight: bold;"
            "}"
            "QPushButton:hover { background: #d0d0d0; }");
    }
    QObject::connect(closeBtn, &QPushButton::clicked, dlg, &QDialog::accept);
    btnRow->addWidget(closeBtn);
    btnRow->addStretch(1);
    mainLayout->addLayout(btnRow);

    packet_analyzer_free_http_info(http);

    /* Stop auto-close timer while dialog is open. deleteLater() AFTER exec()
     * ensures the object is not freed during the dialog's nested event loop
     * (would cause SIGSEGV if the timer also fires deleteLater mid-exec).   */
    if (m_autoCloseTimer) m_autoCloseTimer->stop();
    m_contextMenuActive = true;
    hide();
    dlg->exec();
    deleteLater();
}

/* ------------------------------------------------------------------ */
/* SMB / CIFS Information dialog                                       */
/* ------------------------------------------------------------------ */

/* Map well-known DCE/RPC interface UUIDs to human-readable service names */
static QString dcerpcServiceName(const QString &uuid)
{
    static const struct { const char *uuid; const char *name; } known[] = {
        { "4b324fc8-1670-01d3-1278-5a47bf6ee188", "srvsvc (Server Service)" },
        { "12345778-1234-abcd-ef00-0123456789ac", "samr (Security Account Manager)" },
        { "12345778-1234-abcd-ef00-0123456789ab", "lsarpc (Local Security Authority)" },
        { "338cd001-2244-31f1-aaaa-900038001003", "winreg (Remote Registry)" },
        { "367abb81-9844-35f1-ad32-98f038001003", "svcctl (Service Control Manager)" },
        { "12345678-1234-abcd-ef00-01234567cffb", "wkssvc (Workstation Service)" },
        { "e1af8308-5d1f-11c9-91a4-08002b14a0fa", "epmapper (Endpoint Mapper)" },
        { "3919286a-b10c-11d0-9ba8-00c04fd92ef5", "dssetup (Active Directory Setup)" },
        { "12345678-1234-abcd-ef00-0123456789ab", "spoolss (Print Spooler)" },
        { "6bffd098-a112-3610-9833-46c3f87e345a", "wkssvc (Workstation Service v1)" },
        { "4fc742e0-4a10-11cf-8273-00aa004ae673", "dfsnm (DFS Namespace)" },
        { "1ff70682-0a51-30e8-076d-740be8cee98b", "atsvc (Task Scheduler)" },
        { "86d35949-83c9-4044-b424-db363231fd0c", "ITaskSchedulerService" },
        { NULL, NULL }
    };
    QString lower = uuid.trimmed().toLower();
    for (int i = 0; known[i].uuid; i++) {
        if (lower == QString::fromLatin1(known[i].uuid))
            return QString::fromLatin1(known[i].name);
    }
    return uuid;   /* unknown &mdash; show raw UUID */
}

void ConnectionPopup::showSmbInfoForRow(int row)
{
    if (row < 0 || row >= m_rowData.size() || !m_pair)
        return;

    const RowData &rd = m_rowData[row];

    capture_file *cf = (capture_file *)plugin_if_get_capture_file(
        extract_capture_file, NULL);

    if (!cf) {
        QMessageBox::warning(this, (rd.port == 135) ? "DCE/RPC Information" : "SMB Information",
            "No capture file is currently loaded in Wireshark.");
        return;
    }

    QString src = QString::fromUtf8(m_pair->src_addr);
    QString dst = QString::fromUtf8(m_pair->dst_addr);
    bool looksLikeMAC = (src.count(':') == 5 && dst.count(':') == 5);

    smb_info_t *smb = packet_analyzer_extract_smb_info(
        cf,
        m_pair->src_addr,
        m_pair->dst_addr,
        rd.port,
        looksLikeMAC ? TRUE : FALSE);

    bool dark = isDarkTheme();
    QString dlgTitle = (rd.port == 135) ? "DCE/RPC Information" : "SMB Information";
    QDialog *dlg = new QDialog(nullptr);
    dlg->setWindowTitle(dlgTitle);
    dlg->setAttribute(Qt::WA_DeleteOnClose);
    dlg->setMinimumSize(560, 420);
    dlg->resize(680, 580);
    dlg->setSizeGripEnabled(true);

    QVBoxLayout *mainLayout = new QVBoxLayout(dlg);
    mainLayout->setContentsMargins(16, 16, 16, 16);
    mainLayout->setSpacing(12);

    if (!smb || !smb->found) {
        /* ---- No SMB data: show sorry smiley ---- */
        mainLayout->addStretch(1);

        SorrySmileyWidget *smiley = new SorrySmileyWidget(dlg);
        smiley->setFixedSize(140, 140);
        QHBoxLayout *smileyRow = new QHBoxLayout;
        smileyRow->addStretch(1);
        smileyRow->addWidget(smiley);
        smileyRow->addStretch(1);
        mainLayout->addLayout(smileyRow);

        QString sorryMsg = (rd.port == 135)
            ? "No DCE/RPC protocol data found in the buffer"
            : "No SMB protocol data found in the buffer";
        QLabel *sorryLabel = new QLabel(sorryMsg, dlg);
        sorryLabel->setAlignment(Qt::AlignCenter);
        sorryLabel->setStyleSheet(
            QString("font-size: 16px; font-weight: bold; color: %1; padding: 12px;")
                .arg(dark ? "#e0e0e0" : "#333"));
        mainLayout->addWidget(sorryLabel);

        QString diagText = QString(
            "<div style='text-align:center; color:%1; font-size:12px; padding:8px;'>"
            "Packets matched: <b>%2</b>"
            "</div>")
            .arg(dark ? "#888" : "#999")
            .arg(smb ? smb->matched_packets : 0);
        QLabel *diagLabel = new QLabel(diagText, dlg);
        diagLabel->setAlignment(Qt::AlignCenter);
        diagLabel->setTextFormat(Qt::RichText);
        mainLayout->addWidget(diagLabel);

        mainLayout->addStretch(1);
    } else {
        /* ---- Build rich HTML content ---- */
        QString html;
        QString headingColor = dark ? "#90caf9" : "#1565c0";
        QString textColor    = dark ? "#e0e0e0" : "#222";
        QString dimColor     = dark ? "#999"    : "#666";
        QString valColor     = dark ? "#c8e6c9" : "#1b5e20";

        html += QString("<div style='color:%1;'>").arg(textColor);

        /* ---- Connection ---- */
        html += QString("<h3 style='color:%1; margin-bottom:4px;'>Connection</h3>").arg(headingColor);
        html += QString("<table cellpadding='3'>"
                        "<tr><td style='color:%1;'>Endpoints:</td>"
                        "<td><b>%2</b> &#8596; <b>%3</b></td></tr>"
                        "<tr><td style='color:%1;'>Port:</td>"
                        "<td><b>%4</b></td></tr>"
                        "<tr><td style='color:%1;'>Packets matched:</td>"
                        "<td><b>%5</b></td></tr>"
                        "</table><br>")
                    .arg(dimColor)
                    .arg(src.toHtmlEscaped())
                    .arg(dst.toHtmlEscaped())
                    .arg(rd.port)
                    .arg(smb->matched_packets);

        /* ---- Protocol ---- */
        bool hasProtoData = (smb->dialect || smb->native_os ||
                             smb->is_smb2 || smb->dcerpc_interfaces ||
                             g_hash_table_size(smb->cmd_counts) > 0);
        html += QString("<h3 style='color:%1; margin-bottom:4px;'>Protocol</h3>").arg(headingColor);
        html += "<table cellpadding='3'>";
        if (hasProtoData) {
            if (smb->dcerpc_interfaces && !smb->is_smb2 && !smb->dialect) {
                html += QString("<tr><td style='color:%1;'>Type:</td>"
                                "<td><b>DCE/RPC</b></td></tr>").arg(dimColor);
            } else {
                html += QString("<tr><td style='color:%1;'>Version:</td>"
                                "<td><b>%2</b></td></tr>")
                            .arg(dimColor)
                            .arg(smb->is_smb2 ? "SMB2 / SMB3" : "SMB1 (CIFS)");
            }
        } else {
            html += QString("<tr><td style='color:%1;'>Status:</td>"
                            "<td><b>TCP only</b> &mdash; no SMB/DCE-RPC negotiation detected</td></tr>")
                        .arg(dimColor);
        }
        if (smb->dialect) {
            html += QString("<tr><td style='color:%1;'>Dialect:</td>"
                            "<td style='color:%2;'><b>%3</b></td></tr>")
                        .arg(dimColor).arg(valColor)
                        .arg(QString::fromUtf8(smb->dialect).toHtmlEscaped());
        }
        if (smb->native_os) {
            html += QString("<tr><td style='color:%1;'>Native OS:</td>"
                            "<td><b>%2</b></td></tr>")
                        .arg(dimColor)
                        .arg(QString::fromUtf8(smb->native_os).toHtmlEscaped());
        }
        if (smb->native_lanman) {
            html += QString("<tr><td style='color:%1;'>LAN Manager:</td>"
                            "<td><b>%2</b></td></tr>")
                        .arg(dimColor)
                        .arg(QString::fromUtf8(smb->native_lanman).toHtmlEscaped());
        }
        html += "</table><br>";

        /* ---- Authentication ---- */
        if (smb->auth_username || smb->auth_domain ||
            smb->auth_hostname || smb->target_name) {
            html += QString("<h3 style='color:%1; margin-bottom:4px;'>Authentication</h3>").arg(headingColor);
            html += "<table cellpadding='3'>";
            if (smb->auth_username) {
                html += QString("<tr><td style='color:%1;'>Username:</td>"
                                "<td style='color:%2;'><b>%3</b></td></tr>")
                            .arg(dimColor).arg(valColor)
                            .arg(QString::fromUtf8(smb->auth_username).toHtmlEscaped());
            }
            if (smb->auth_domain) {
                html += QString("<tr><td style='color:%1;'>Domain:</td>"
                                "<td><b>%2</b></td></tr>")
                            .arg(dimColor)
                            .arg(QString::fromUtf8(smb->auth_domain).toHtmlEscaped());
            }
            if (smb->auth_hostname) {
                html += QString("<tr><td style='color:%1;'>Hostname:</td>"
                                "<td><b>%2</b></td></tr>")
                            .arg(dimColor)
                            .arg(QString::fromUtf8(smb->auth_hostname).toHtmlEscaped());
            }
            if (smb->target_name) {
                html += QString("<tr><td style='color:%1;'>Target (Server):</td>"
                                "<td><b>%2</b></td></tr>")
                            .arg(dimColor)
                            .arg(QString::fromUtf8(smb->target_name).toHtmlEscaped());
            }
            html += "</table><br>";
        }

        /* ---- Shares ---- */
        if (smb->tree_paths) {
            html += QString("<h3 style='color:%1; margin-bottom:4px;'>Shares</h3>").arg(headingColor);
            for (GList *l = smb->tree_paths; l; l = l->next) {
                const gchar *tp = (const gchar *)l->data;
                if (tp) html += QString("&nbsp;&nbsp;&#8226; <b style='color:%1;'>%2</b><br>")
                                    .arg(valColor).arg(QString::fromUtf8(tp).toHtmlEscaped());
            }
            html += "<br>";
        }

        /* ---- Named Pipes & DCE/RPC Services ---- */
        if (smb->named_pipes || smb->dcerpc_interfaces) {
            html += QString("<h3 style='color:%1; margin-bottom:4px;'>Named Pipes &amp; Services</h3>").arg(headingColor);
            if (smb->named_pipes) {
                html += QString("<div style='margin-bottom:4px;'>"
                                "<span style='color:%1;'>Named Pipes:</span></div>")
                            .arg(dimColor);
                for (GList *l = smb->named_pipes; l; l = l->next) {
                    const gchar *np = (const gchar *)l->data;
                    if (np) html += QString("&nbsp;&nbsp;&#8226; <span style='font-family:monospace;'><b>%1</b></span><br>")
                                        .arg(QString::fromUtf8(np).toHtmlEscaped());
                }
            }
            if (smb->dcerpc_interfaces) {
                html += QString("<div style='margin-top:6px; margin-bottom:4px;'>"
                                "<span style='color:%1;'>DCE/RPC Interfaces:</span></div>")
                            .arg(dimColor);
                for (GList *l = smb->dcerpc_interfaces; l; l = l->next) {
                    const gchar *iface = (const gchar *)l->data;
                    if (iface) {
                        QString resolved = dcerpcServiceName(QString::fromUtf8(iface));
                        html += QString("&nbsp;&nbsp;&#8226; <b style='color:%1;'>%2</b><br>")
                                    .arg(valColor).arg(resolved.toHtmlEscaped());
                    }
                }
            }
            html += "<br>";
        }

        /* ---- Files ---- */
        if (smb->filenames) {
            guint shown = g_list_length(smb->filenames);
            QString fileHeading = (smb->filename_total > shown)
                ? QString("Files (showing %1 of %2 unique)").arg(shown).arg(smb->filename_total)
                : QString("Files (%1)").arg(shown);
            html += QString("<h3 style='color:%1; margin-bottom:4px;'>%2</h3>")
                        .arg(headingColor).arg(fileHeading);
            int count = 0;
            for (GList *l = smb->filenames; l; l = l->next) {
                const gchar *fn = (const gchar *)l->data;
                if (!fn) continue;
                count++;
                if (count > 50) {
                    html += QString("<span style='color:%1;'>... and %2 more</span><br>")
                                .arg(dimColor).arg(shown - 50);
                    break;
                }
                html += QString("&nbsp;&nbsp;&#8226; <span style='font-family:monospace; font-size:12px;'>%1</span><br>")
                            .arg(QString::fromUtf8(fn).toHtmlEscaped());
            }
            html += "<br>";
        }

        /* ---- Message Statistics ---- */
        if (smb->cmd_counts && g_hash_table_size(smb->cmd_counts) > 0) {
            html += QString("<h3 style='color:%1; margin-bottom:4px;'>Message Statistics</h3>").arg(headingColor);
            html += "<table cellpadding='3'>";

            /* Collect and sort by count descending */
            GHashTableIter iter;
            gpointer key, value;
            QList<QPair<QString, guint>> cmdList;
            g_hash_table_iter_init(&iter, smb->cmd_counts);
            while (g_hash_table_iter_next(&iter, &key, &value)) {
                cmdList.append(qMakePair(
                    QString::fromUtf8((const gchar *)key),
                    GPOINTER_TO_UINT(value)));
            }
            std::sort(cmdList.begin(), cmdList.end(),
                      [](const QPair<QString,guint> &a, const QPair<QString,guint> &b) {
                          return a.second > b.second;
                      });

            for (const auto &cmd : cmdList) {
                html += QString("<tr><td style='color:%1;'><b>%2</b></td>"
                                "<td style='color:%3;'>&#215; %4</td></tr>")
                            .arg(valColor)
                            .arg(cmd.first.toHtmlEscaped())
                            .arg(dimColor)
                            .arg(cmd.second);
            }
            html += "</table><br>";
        }

        html += "</div>";

        QTextEdit *textEdit = new QTextEdit(dlg);
        textEdit->setReadOnly(true);
        textEdit->setHtml(html);
        if (dark) {
            textEdit->setStyleSheet(
                "QTextEdit {"
                "  background: #1e1e1e;"
                "  color: #e0e0e0;"
                "  border: 1px solid #444;"
                "  border-radius: 4px;"
                "  padding: 8px;"
                "}");
        } else {
            textEdit->setStyleSheet(
                "QTextEdit {"
                "  background: #fafafa;"
                "  color: #222;"
                "  border: 1px solid #ccc;"
                "  border-radius: 4px;"
                "  padding: 8px;"
                "}");
        }
        mainLayout->addWidget(textEdit);
    }

    /* Close button */
    QHBoxLayout *btnRow = new QHBoxLayout;
    btnRow->addStretch(1);
    QPushButton *closeBtn = new QPushButton("Close", dlg);
    closeBtn->setFixedWidth(100);
    if (dark) {
        closeBtn->setStyleSheet(
            "QPushButton {"
            "  background: #444; color: #e0e0e0; border: 1px solid #666;"
            "  border-radius: 4px; padding: 6px 16px; font-weight: bold;"
            "}"
            "QPushButton:hover { background: #555; }");
    } else {
        closeBtn->setStyleSheet(
            "QPushButton {"
            "  background: #e0e0e0; color: #222; border: 1px solid #aaa;"
            "  border-radius: 4px; padding: 6px 16px; font-weight: bold;"
            "}"
            "QPushButton:hover { background: #d0d0d0; }");
    }
    QObject::connect(closeBtn, &QPushButton::clicked, dlg, &QDialog::accept);
    btnRow->addWidget(closeBtn);
    btnRow->addStretch(1);
    mainLayout->addLayout(btnRow);

    packet_analyzer_free_smb_info(smb);

    /* Stop auto-close timer while dialog is open. deleteLater() AFTER exec()
     * ensures the object is not freed during the dialog's nested event loop
     * (would cause SIGSEGV if the timer also fires deleteLater mid-exec).   */
    if (m_autoCloseTimer) m_autoCloseTimer->stop();
    m_contextMenuActive = true;
    hide();
    dlg->exec();
    deleteLater();
}

/* ------------------------------------------------------------------ */
/* Kerberos Information dialog                                          */
/* ------------------------------------------------------------------ */

/* Return TRUE if the etype label looks like a weak cipher (RC4, DES, etc.) */
static bool isWeakKerberosEtype(const QString &label)
{
    QString lower = label.toLower();
    return lower.contains("rc4") ||
           lower.contains("arcfour") ||
           lower.contains("des-cbc") ||
           lower.contains("des3");
}

void ConnectionPopup::showKerberosInfoForRow(int row)
{
    if (row < 0 || row >= m_rowData.size() || !m_pair)
        return;

    const RowData &rd = m_rowData[row];

    capture_file *cf = (capture_file *)plugin_if_get_capture_file(
        extract_capture_file, NULL);

    if (!cf) {
        QMessageBox::warning(this, "Kerberos Information",
            "No capture file is currently loaded in Wireshark.");
        return;
    }

    QString src = QString::fromUtf8(m_pair->src_addr);
    QString dst = QString::fromUtf8(m_pair->dst_addr);
    bool looksLikeMAC = (src.count(':') == 5 && dst.count(':') == 5);

    kerberos_info_t *krb = packet_analyzer_extract_kerberos_info(
        cf,
        m_pair->src_addr,
        m_pair->dst_addr,
        rd.port,
        looksLikeMAC ? TRUE : FALSE);

    bool dark = isDarkTheme();
    QDialog *dlg = new QDialog(nullptr);
    dlg->setWindowTitle("Kerberos Information");
    dlg->setAttribute(Qt::WA_DeleteOnClose);
    dlg->setMinimumSize(560, 420);
    dlg->resize(680, 600);
    dlg->setSizeGripEnabled(true);

    QVBoxLayout *mainLayout = new QVBoxLayout(dlg);
    mainLayout->setContentsMargins(16, 16, 16, 16);
    mainLayout->setSpacing(12);

    if (!krb || !krb->found) {
        /* ---- No Kerberos data: show sorry smiley ---- */
        mainLayout->addStretch(1);

        SorrySmileyWidget *smiley = new SorrySmileyWidget(dlg);
        smiley->setFixedSize(140, 140);
        QHBoxLayout *smileyRow = new QHBoxLayout;
        smileyRow->addStretch(1);
        smileyRow->addWidget(smiley);
        smileyRow->addStretch(1);
        mainLayout->addLayout(smileyRow);

        QLabel *sorryLabel = new QLabel(
            "No Kerberos protocol data found in the buffer", dlg);
        sorryLabel->setAlignment(Qt::AlignCenter);
        sorryLabel->setStyleSheet(
            QString("font-size: 16px; font-weight: bold; color: %1; padding: 12px;")
                .arg(dark ? "#e0e0e0" : "#333"));
        mainLayout->addWidget(sorryLabel);

        QString diagText = QString(
            "<div style='text-align:center; color:%1; font-size:12px; padding:8px;'>"
            "Packets matched: <b>%2</b>"
            "</div>")
            .arg(dark ? "#888" : "#999")
            .arg(krb ? krb->matched_packets : 0);
        QLabel *diagLabel = new QLabel(diagText, dlg);
        diagLabel->setAlignment(Qt::AlignCenter);
        diagLabel->setTextFormat(Qt::RichText);
        mainLayout->addWidget(diagLabel);

        mainLayout->addStretch(1);
    } else {
        /* ---- Build rich HTML content ---- */
        QString html;
        QString headingColor = dark ? "#90caf9" : "#1565c0";
        QString textColor    = dark ? "#e0e0e0" : "#222";
        QString dimColor     = dark ? "#999"    : "#666";
        QString valColor     = dark ? "#c8e6c9" : "#1b5e20";
        QString warnColor    = dark ? "#ffab91" : "#bf360c";

        html += QString("<div style='color:%1;'>").arg(textColor);

        /* ---- Connection ---- */
        html += QString("<h3 style='color:%1; margin-bottom:4px;'>Connection</h3>").arg(headingColor);
        html += QString("<table cellpadding='3'>"
                        "<tr><td style='color:%1;'>Endpoints:</td>"
                        "<td><b>%2</b> &#8596; <b>%3</b></td></tr>"
                        "<tr><td style='color:%1;'>Port:</td>"
                        "<td><b>%4</b> (%5)</td></tr>"
                        "<tr><td style='color:%1;'>Packets matched:</td>"
                        "<td><b>%6</b></td></tr>"
                        "</table><br>")
                    .arg(dimColor)
                    .arg(src.toHtmlEscaped())
                    .arg(dst.toHtmlEscaped())
                    .arg(rd.port)
                    .arg(rd.isTcp ? "TCP" : "UDP")
                    .arg(krb->matched_packets);

        /* ---- Realm ---- */
        if (krb->realm || krb->client_realm) {
            html += QString("<h3 style='color:%1; margin-bottom:4px;'>Realm</h3>").arg(headingColor);
            html += "<table cellpadding='3'>";
            if (krb->realm) {
                html += QString("<tr><td style='color:%1;'>Realm:</td>"
                                "<td style='color:%2;'><b>%3</b></td></tr>")
                            .arg(dimColor).arg(valColor)
                            .arg(QString::fromUtf8(krb->realm).toHtmlEscaped());
            }
            if (krb->client_realm && g_strcmp0(krb->client_realm, krb->realm) != 0) {
                html += QString("<tr><td style='color:%1;'>Client Realm:</td>"
                                "<td style='color:%2;'><b>%3</b></td></tr>")
                            .arg(dimColor).arg(valColor)
                            .arg(QString::fromUtf8(krb->client_realm).toHtmlEscaped());
            }
            html += "</table><br>";
        }

        /* ---- Message Statistics ---- */
        if (krb->msg_type_counts && g_hash_table_size(krb->msg_type_counts) > 0) {
            html += QString("<h3 style='color:%1; margin-bottom:4px;'>Message Types</h3>").arg(headingColor);
            html += "<table cellpadding='3'>";

            GHashTableIter iter;
            gpointer key, value;
            QList<QPair<QString, guint>> msgList;
            g_hash_table_iter_init(&iter, krb->msg_type_counts);
            while (g_hash_table_iter_next(&iter, &key, &value)) {
                msgList.append(qMakePair(
                    QString::fromUtf8((const gchar *)key),
                    GPOINTER_TO_UINT(value)));
            }
            std::sort(msgList.begin(), msgList.end(),
                      [](const QPair<QString,guint> &a, const QPair<QString,guint> &b) {
                          return a.second > b.second;
                      });

            for (const auto &msg : msgList) {
                html += QString("<tr><td style='color:%1;'><b>%2</b></td>"
                                "<td style='color:%3;'>&#215; %4</td></tr>")
                            .arg(valColor)
                            .arg(msg.first.toHtmlEscaped())
                            .arg(dimColor)
                            .arg(msg.second);
            }
            html += "</table><br>";
        }

        /* ---- Client Principals ---- */
        if (krb->client_names) {
            html += QString("<h3 style='color:%1; margin-bottom:4px;'>Client Principals</h3>").arg(headingColor);
            for (GList *l = krb->client_names; l; l = l->next) {
                const gchar *cn = (const gchar *)l->data;
                if (cn) html += QString("&nbsp;&nbsp;&#8226; <b style='color:%1;'>%2</b><br>")
                                    .arg(valColor).arg(QString::fromUtf8(cn).toHtmlEscaped());
            }
            html += "<br>";
        }

        /* ---- Service Principals ---- */
        if (krb->service_names) {
            html += QString("<h3 style='color:%1; margin-bottom:4px;'>Service Principals</h3>").arg(headingColor);
            for (GList *l = krb->service_names; l; l = l->next) {
                const gchar *sn = (const gchar *)l->data;
                if (sn) html += QString("&nbsp;&nbsp;&#8226; <b style='color:%1;'>%2</b><br>")
                                    .arg(valColor).arg(QString::fromUtf8(sn).toHtmlEscaped());
            }
            html += "<br>";
        }

        /* ---- Encryption Types ---- */
        if (krb->encryption_types) {
            html += QString("<h3 style='color:%1; margin-bottom:4px;'>Encryption Types</h3>").arg(headingColor);
            bool hasWeak = false;
            for (GList *l = krb->encryption_types; l; l = l->next) {
                const gchar *et = (const gchar *)l->data;
                if (!et) continue;
                QString etStr = QString::fromUtf8(et);
                bool weak = isWeakKerberosEtype(etStr);
                if (weak) hasWeak = true;
                QString color = weak ? warnColor : valColor;
                QString suffix = weak ? " &#9888; <i>weak</i>" : "";
                html += QString("&nbsp;&nbsp;&#8226; <b style='color:%1;'>%2</b>%3<br>")
                            .arg(color).arg(etStr.toHtmlEscaped()).arg(suffix);
            }
            if (hasWeak) {
                html += QString("<div style='margin-top:4px; color:%1; font-size:11px;'>"
                                "&#9888; Weak encryption detected &mdash; consider enforcing AES-only policy"
                                "</div>")
                            .arg(warnColor);
            }
            html += "<br>";
        }

        /* ---- Errors ---- */
        if ((krb->error_counts && g_hash_table_size(krb->error_counts) > 0) ||
            krb->error_texts) {
            html += QString("<h3 style='color:%1; margin-bottom:4px;'>Errors</h3>").arg(headingColor);

            if (krb->error_counts && g_hash_table_size(krb->error_counts) > 0) {
                html += "<table cellpadding='3'>";

                GHashTableIter iter;
                gpointer key, value;
                QList<QPair<QString, guint>> errList;
                g_hash_table_iter_init(&iter, krb->error_counts);
                while (g_hash_table_iter_next(&iter, &key, &value)) {
                    errList.append(qMakePair(
                        QString::fromUtf8((const gchar *)key),
                        GPOINTER_TO_UINT(value)));
                }
                std::sort(errList.begin(), errList.end(),
                          [](const QPair<QString,guint> &a, const QPair<QString,guint> &b) {
                              return a.second > b.second;
                          });

                for (const auto &e : errList) {
                    html += QString("<tr><td style='color:%1;'><b>%2</b></td>"
                                    "<td style='color:%3;'>&#215; %4</td></tr>")
                                .arg(warnColor)
                                .arg(e.first.toHtmlEscaped())
                                .arg(dimColor)
                                .arg(e.second);
                }
                html += "</table>";
            }

            if (krb->error_texts) {
                html += QString("<div style='margin-top:6px;'>"
                                "<span style='color:%1;'>Error Text:</span></div>")
                            .arg(dimColor);
                for (GList *l = krb->error_texts; l; l = l->next) {
                    const gchar *et = (const gchar *)l->data;
                    if (et) html += QString("&nbsp;&nbsp;&#8226; <i>%1</i><br>")
                                        .arg(QString::fromUtf8(et).toHtmlEscaped());
                }
            }
            html += "<br>";
        }

        html += "</div>";

        QTextEdit *textEdit = new QTextEdit(dlg);
        textEdit->setReadOnly(true);
        textEdit->setHtml(html);
        if (dark) {
            textEdit->setStyleSheet(
                "QTextEdit {"
                "  background: #1e1e1e;"
                "  color: #e0e0e0;"
                "  border: 1px solid #444;"
                "  border-radius: 4px;"
                "  padding: 8px;"
                "}");
        } else {
            textEdit->setStyleSheet(
                "QTextEdit {"
                "  background: #fafafa;"
                "  color: #222;"
                "  border: 1px solid #ccc;"
                "  border-radius: 4px;"
                "  padding: 8px;"
                "}");
        }
        mainLayout->addWidget(textEdit);
    }

    /* Close button */
    QHBoxLayout *btnRow = new QHBoxLayout;
    btnRow->addStretch(1);
    QPushButton *closeBtn = new QPushButton("Close", dlg);
    closeBtn->setFixedWidth(100);
    if (dark) {
        closeBtn->setStyleSheet(
            "QPushButton {"
            "  background: #444; color: #e0e0e0; border: 1px solid #666;"
            "  border-radius: 4px; padding: 6px 16px; font-weight: bold;"
            "}"
            "QPushButton:hover { background: #555; }");
    } else {
        closeBtn->setStyleSheet(
            "QPushButton {"
            "  background: #e0e0e0; color: #222; border: 1px solid #aaa;"
            "  border-radius: 4px; padding: 6px 16px; font-weight: bold;"
            "}"
            "QPushButton:hover { background: #d0d0d0; }");
    }
    QObject::connect(closeBtn, &QPushButton::clicked, dlg, &QDialog::accept);
    btnRow->addWidget(closeBtn);
    btnRow->addStretch(1);
    mainLayout->addLayout(btnRow);

    packet_analyzer_free_kerberos_info(krb);

    /* Stop auto-close timer while dialog is open. deleteLater() AFTER exec()
     * ensures the object is not freed during the dialog's nested event loop
     * (would cause SIGSEGV if the timer also fires deleteLater mid-exec).   */
    if (m_autoCloseTimer) m_autoCloseTimer->stop();
    m_contextMenuActive = true;
    hide();
    dlg->exec();
    deleteLater();
}

/* ------------------------------------------------------------------ */
/* Email Protocol Information dialog (SMTP / IMAP / POP3)               */
/* ------------------------------------------------------------------ */

static QString emailProtocolName(quint16 port)
{
    switch (port) {
    case 25:  return "SMTP";
    case 587: return "SMTP (Submission)";
    case 465: return "SMTPS";
    case 143: return "IMAP";
    case 993: return "IMAPS";
    case 110: return "POP3";
    case 995: return "POP3S";
    default:  return "Email";
    }
}

static QString emailDialogTitle(quint16 port)
{
    switch (port) {
    case 25: case 587: case 465: return "SMTP Information";
    case 143: case 993:          return "IMAP Information";
    case 110: case 995:          return "POP3 Information";
    default:                     return "Email Protocol Information";
    }
}

void ConnectionPopup::showEmailInfoForRow(int row)
{
    if (row < 0 || row >= m_rowData.size() || !m_pair)
        return;

    const RowData &rd = m_rowData[row];

    capture_file *cf = (capture_file *)plugin_if_get_capture_file(
        extract_capture_file, NULL);

    QString dlgTitle = emailDialogTitle(rd.port);

    if (!cf) {
        QMessageBox::warning(this, dlgTitle,
            "No capture file is currently loaded in Wireshark.");
        return;
    }

    QString src = QString::fromUtf8(m_pair->src_addr);
    QString dst = QString::fromUtf8(m_pair->dst_addr);
    bool looksLikeMAC = (src.count(':') == 5 && dst.count(':') == 5);

    email_info_t *em = packet_analyzer_extract_email_info(
        cf,
        m_pair->src_addr,
        m_pair->dst_addr,
        rd.port,
        looksLikeMAC ? TRUE : FALSE);

    bool dark = isDarkTheme();
    QDialog *dlg = new QDialog(nullptr);
    dlg->setWindowTitle(dlgTitle);
    dlg->setAttribute(Qt::WA_DeleteOnClose);
    dlg->setMinimumSize(560, 420);
    dlg->resize(700, 620);
    dlg->setSizeGripEnabled(true);

    QVBoxLayout *mainLayout = new QVBoxLayout(dlg);
    mainLayout->setContentsMargins(16, 16, 16, 16);
    mainLayout->setSpacing(12);

    if (!em || !em->found) {
        /* ---- No data: show sorry smiley ---- */
        mainLayout->addStretch(1);

        SorrySmileyWidget *smiley = new SorrySmileyWidget(dlg);
        smiley->setFixedSize(140, 140);
        QHBoxLayout *smileyRow = new QHBoxLayout;
        smileyRow->addStretch(1);
        smileyRow->addWidget(smiley);
        smileyRow->addStretch(1);
        mainLayout->addLayout(smileyRow);

        QLabel *sorryLabel = new QLabel(
            QString("No %1 protocol data found in the buffer")
                .arg(emailProtocolName(rd.port)), dlg);
        sorryLabel->setAlignment(Qt::AlignCenter);
        sorryLabel->setStyleSheet(
            QString("font-size: 16px; font-weight: bold; color: %1; padding: 12px;")
                .arg(dark ? "#e0e0e0" : "#333"));
        mainLayout->addWidget(sorryLabel);

        QString diagText = QString(
            "<div style='text-align:center; color:%1; font-size:12px; padding:8px;'>"
            "Packets matched: <b>%2</b>"
            "</div>")
            .arg(dark ? "#888" : "#999")
            .arg(em ? em->matched_packets : 0);
        QLabel *diagLabel = new QLabel(diagText, dlg);
        diagLabel->setAlignment(Qt::AlignCenter);
        diagLabel->setTextFormat(Qt::RichText);
        mainLayout->addWidget(diagLabel);

        mainLayout->addStretch(1);
    } else {
        /* ---- Build rich HTML content ---- */
        QString html;
        QString headingColor = dark ? "#90caf9" : "#1565c0";
        QString textColor    = dark ? "#e0e0e0" : "#222";
        QString dimColor     = dark ? "#999"    : "#666";
        QString valColor     = dark ? "#c8e6c9" : "#1b5e20";

        html += QString("<div style='color:%1;'>").arg(textColor);

        /* ---- Connection ---- */
        html += QString("<h3 style='color:%1; margin-bottom:4px;'>Connection</h3>").arg(headingColor);
        html += QString("<table cellpadding='3'>"
                        "<tr><td style='color:%1;'>Protocol:</td>"
                        "<td><b>%2</b></td></tr>"
                        "<tr><td style='color:%1;'>Endpoints:</td>"
                        "<td><b>%3</b> &#8596; <b>%4</b></td></tr>"
                        "<tr><td style='color:%1;'>Port:</td>"
                        "<td><b>%5</b></td></tr>"
                        "<tr><td style='color:%1;'>Packets matched:</td>"
                        "<td><b>%6</b></td></tr>"
                        "</table><br>")
                    .arg(dimColor)
                    .arg(emailProtocolName(rd.port))
                    .arg(src.toHtmlEscaped())
                    .arg(dst.toHtmlEscaped())
                    .arg(rd.port)
                    .arg(em->matched_packets);

        /* ---- Authentication ---- */
        if (em->auth_username) {
            html += QString("<h3 style='color:%1; margin-bottom:4px;'>Authentication</h3>").arg(headingColor);
            html += QString("<table cellpadding='3'>"
                            "<tr><td style='color:%1;'>Username:</td>"
                            "<td style='color:%2;'><b>%3</b></td></tr>"
                            "</table><br>")
                        .arg(dimColor).arg(valColor)
                        .arg(QString::fromUtf8(em->auth_username).toHtmlEscaped());
        }

        /* ---- SMTP Envelope (MAIL FROM / RCPT TO / EHLO) ---- */
        if (em->ehlo_domains) {
            html += QString("<h3 style='color:%1; margin-bottom:4px;'>Client Identity</h3>").arg(headingColor);
            for (GList *l = em->ehlo_domains; l; l = l->next) {
                const gchar *d = (const gchar *)l->data;
                if (d) html += QString("&nbsp;&nbsp;EHLO <b style='color:%1;'>%2</b><br>")
                                    .arg(valColor).arg(QString::fromUtf8(d).toHtmlEscaped());
            }
            html += "<br>";
        }

        if (em->mail_from || em->rcpt_to) {
            html += QString("<h3 style='color:%1; margin-bottom:4px;'>Envelope</h3>").arg(headingColor);
            if (em->mail_from) {
                for (GList *l = em->mail_from; l; l = l->next) {
                    const gchar *mf = (const gchar *)l->data;
                    if (mf) html += QString("&nbsp;&nbsp;MAIL <b style='color:%1;'>%2</b><br>")
                                        .arg(valColor).arg(QString::fromUtf8(mf).toHtmlEscaped());
                }
            }
            if (em->rcpt_to) {
                for (GList *l = em->rcpt_to; l; l = l->next) {
                    const gchar *rt = (const gchar *)l->data;
                    if (rt) html += QString("&nbsp;&nbsp;RCPT <b style='color:%1;'>%2</b><br>")
                                        .arg(valColor).arg(QString::fromUtf8(rt).toHtmlEscaped());
                }
            }
            html += "<br>";
        }

        /* ---- IMAP Folders ---- */
        if (em->folders) {
            html += QString("<h3 style='color:%1; margin-bottom:4px;'>Mailbox Folders</h3>").arg(headingColor);
            for (GList *l = em->folders; l; l = l->next) {
                const gchar *f = (const gchar *)l->data;
                if (f) html += QString("&nbsp;&nbsp;&#8226; <b style='color:%1;'>%2</b><br>")
                                    .arg(valColor).arg(QString::fromUtf8(f).toHtmlEscaped());
            }
            html += "<br>";
        }

        /* ---- Message Headers (from IMF) ---- */
        bool hasIMF = (em->from_addrs || em->to_addrs || em->subjects ||
                       em->user_agents || em->content_types);
        if (hasIMF) {
            html += QString("<h3 style='color:%1; margin-bottom:4px;'>Message Headers</h3>").arg(headingColor);
            html += "<table cellpadding='3'>";
            if (em->from_addrs) {
                for (GList *l = em->from_addrs; l; l = l->next) {
                    const gchar *a = (const gchar *)l->data;
                    if (a) html += QString("<tr><td style='color:%1;'>From:</td>"
                                           "<td style='color:%2;'><b>%3</b></td></tr>")
                                       .arg(dimColor).arg(valColor)
                                       .arg(QString::fromUtf8(a).toHtmlEscaped());
                }
            }
            if (em->to_addrs) {
                for (GList *l = em->to_addrs; l; l = l->next) {
                    const gchar *a = (const gchar *)l->data;
                    if (a) html += QString("<tr><td style='color:%1;'>To:</td>"
                                           "<td><b>%2</b></td></tr>")
                                       .arg(dimColor)
                                       .arg(QString::fromUtf8(a).toHtmlEscaped());
                }
            }
            html += "</table>";

            if (em->subjects) {
                html += QString("<div style='margin-top:6px;'>"
                                "<span style='color:%1;'>Subjects:</span></div>")
                            .arg(dimColor);
                int count = 0;
                for (GList *l = em->subjects; l; l = l->next) {
                    const gchar *s = (const gchar *)l->data;
                    if (!s) continue;
                    count++;
                    if (count > 30) {
                        guint total = g_list_length(em->subjects);
                        html += QString("<span style='color:%1;'>... and %2 more</span><br>")
                                    .arg(dimColor).arg(total - 30);
                        break;
                    }
                    html += QString("&nbsp;&nbsp;&#8226; <i>%1</i><br>")
                                .arg(QString::fromUtf8(s).toHtmlEscaped());
                }
            }

            if (em->user_agents) {
                html += QString("<div style='margin-top:6px;'>"
                                "<span style='color:%1;'>User-Agent:</span></div>")
                            .arg(dimColor);
                for (GList *l = em->user_agents; l; l = l->next) {
                    const gchar *ua = (const gchar *)l->data;
                    if (ua) html += QString("&nbsp;&nbsp;&#8226; <span style='font-family:monospace; font-size:12px;'>%1</span><br>")
                                        .arg(QString::fromUtf8(ua).toHtmlEscaped());
                }
            }

            if (em->content_types) {
                html += QString("<div style='margin-top:6px;'>"
                                "<span style='color:%1;'>Content-Types:</span></div>")
                            .arg(dimColor);
                for (GList *l = em->content_types; l; l = l->next) {
                    const gchar *ct = (const gchar *)l->data;
                    if (ct) html += QString("&nbsp;&nbsp;&#8226; <span style='font-family:monospace; font-size:12px;'>%1</span><br>")
                                        .arg(QString::fromUtf8(ct).toHtmlEscaped());
                }
            }
            html += "<br>";
        }

        /* ---- Command Statistics ---- */
        if (em->cmd_counts && g_hash_table_size(em->cmd_counts) > 0) {
            html += QString("<h3 style='color:%1; margin-bottom:4px;'>Commands</h3>").arg(headingColor);
            html += "<table cellpadding='3'>";

            GHashTableIter iter;
            gpointer key, value;
            QList<QPair<QString, guint>> cmdList;
            g_hash_table_iter_init(&iter, em->cmd_counts);
            while (g_hash_table_iter_next(&iter, &key, &value)) {
                cmdList.append(qMakePair(
                    QString::fromUtf8((const gchar *)key),
                    GPOINTER_TO_UINT(value)));
            }
            std::sort(cmdList.begin(), cmdList.end(),
                      [](const QPair<QString,guint> &a, const QPair<QString,guint> &b) {
                          return a.second > b.second;
                      });

            for (const auto &cmd : cmdList) {
                html += QString("<tr><td style='color:%1;'><b>%2</b></td>"
                                "<td style='color:%3;'>&#215; %4</td></tr>")
                            .arg(valColor)
                            .arg(cmd.first.toHtmlEscaped())
                            .arg(dimColor)
                            .arg(cmd.second);
            }
            html += "</table><br>";
        }

        /* ---- Response Statistics ---- */
        if (em->response_counts && g_hash_table_size(em->response_counts) > 0) {
            html += QString("<h3 style='color:%1; margin-bottom:4px;'>Responses</h3>").arg(headingColor);
            html += "<table cellpadding='3'>";

            GHashTableIter iter;
            gpointer key, value;
            QList<QPair<QString, guint>> rspList;
            g_hash_table_iter_init(&iter, em->response_counts);
            while (g_hash_table_iter_next(&iter, &key, &value)) {
                rspList.append(qMakePair(
                    QString::fromUtf8((const gchar *)key),
                    GPOINTER_TO_UINT(value)));
            }
            std::sort(rspList.begin(), rspList.end(),
                      [](const QPair<QString,guint> &a, const QPair<QString,guint> &b) {
                          return a.second > b.second;
                      });

            for (const auto &rsp : rspList) {
                html += QString("<tr><td style='color:%1;'><b>%2</b></td>"
                                "<td style='color:%3;'>&#215; %4</td></tr>")
                            .arg(valColor)
                            .arg(rsp.first.toHtmlEscaped())
                            .arg(dimColor)
                            .arg(rsp.second);
            }
            html += "</table><br>";
        }

        html += "</div>";

        QTextEdit *textEdit = new QTextEdit(dlg);
        textEdit->setReadOnly(true);
        textEdit->setHtml(html);
        if (dark) {
            textEdit->setStyleSheet(
                "QTextEdit {"
                "  background: #1e1e1e;"
                "  color: #e0e0e0;"
                "  border: 1px solid #444;"
                "  border-radius: 4px;"
                "  padding: 8px;"
                "}");
        } else {
            textEdit->setStyleSheet(
                "QTextEdit {"
                "  background: #fafafa;"
                "  color: #222;"
                "  border: 1px solid #ccc;"
                "  border-radius: 4px;"
                "  padding: 8px;"
                "}");
        }
        mainLayout->addWidget(textEdit);
    }

    /* Close button */
    QHBoxLayout *btnRow = new QHBoxLayout;
    btnRow->addStretch(1);
    QPushButton *closeBtn = new QPushButton("Close", dlg);
    closeBtn->setFixedWidth(100);
    if (dark) {
        closeBtn->setStyleSheet(
            "QPushButton {"
            "  background: #444; color: #e0e0e0; border: 1px solid #666;"
            "  border-radius: 4px; padding: 6px 16px; font-weight: bold;"
            "}"
            "QPushButton:hover { background: #555; }");
    } else {
        closeBtn->setStyleSheet(
            "QPushButton {"
            "  background: #e0e0e0; color: #222; border: 1px solid #aaa;"
            "  border-radius: 4px; padding: 6px 16px; font-weight: bold;"
            "}"
            "QPushButton:hover { background: #d0d0d0; }");
    }
    QObject::connect(closeBtn, &QPushButton::clicked, dlg, &QDialog::accept);
    btnRow->addWidget(closeBtn);
    btnRow->addStretch(1);
    mainLayout->addLayout(btnRow);

    packet_analyzer_free_email_info(em);

    /* Stop auto-close timer while dialog is open. deleteLater() AFTER exec()
     * ensures the object is not freed during the dialog's nested event loop
     * (would cause SIGSEGV if the timer also fires deleteLater mid-exec).   */
    if (m_autoCloseTimer) m_autoCloseTimer->stop();
    m_contextMenuActive = true;
    hide();
    dlg->exec();
    deleteLater();
}

/* ------------------------------------------------------------------ */
/* SQL Database Information Dialog                                       */
/* ------------------------------------------------------------------ */

static QString sqlDialogTitle(quint16 port)
{
    switch (port) {
    case 1433: return "MSSQL / TDS Information";
    case 3306: return "MySQL / MariaDB Information";
    case 5432: return "PostgreSQL Information";
    default:   return "SQL Database Information";
    }
}

static QString sqlProtocolName(quint16 port)
{
    switch (port) {
    case 1433: return "MSSQL";
    case 3306: return "MySQL";
    case 5432: return "PostgreSQL";
    default:   return "SQL";
    }
}

/* Helper: render a hash table of string→count as a sorted HTML table */
static QString renderHashCountTable(GHashTable *ht, const QString &headingColor,
                                    const QString &valColor, const QString &dimColor,
                                    const QString &title)
{
    if (!ht || g_hash_table_size(ht) == 0) return QString();

    QString html;
    html += QString("<h3 style='color:%1; margin-bottom:4px;'>%2</h3>").arg(headingColor).arg(title);
    html += "<table cellpadding='3'>";

    GHashTableIter iter;
    gpointer key, value;
    QList<QPair<QString, guint>> list;
    g_hash_table_iter_init(&iter, ht);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        list.append(qMakePair(
            QString::fromUtf8((const gchar *)key),
            GPOINTER_TO_UINT(value)));
    }
    std::sort(list.begin(), list.end(),
              [](const QPair<QString,guint> &a, const QPair<QString,guint> &b) {
                  return a.second > b.second;
              });

    for (const auto &item : list) {
        html += QString("<tr><td style='color:%1;'><b>%2</b></td>"
                        "<td style='color:%3;'>&#215; %4</td></tr>")
                    .arg(valColor)
                    .arg(item.first.toHtmlEscaped())
                    .arg(dimColor)
                    .arg(item.second);
    }
    html += "</table><br>";
    return html;
}

/* Helper: create a standard info dialog shell (returns mainLayout) */
static QDialog* createInfoDialog(const QString &title, [[maybe_unused]] bool dark, QVBoxLayout **outLayout)
{
    QDialog *dlg = new QDialog(nullptr);
    dlg->setWindowTitle(title);
    dlg->setAttribute(Qt::WA_DeleteOnClose);
    dlg->setMinimumSize(560, 420);
    dlg->resize(700, 620);
    dlg->setSizeGripEnabled(true);

    QVBoxLayout *mainLayout = new QVBoxLayout(dlg);
    mainLayout->setContentsMargins(16, 16, 16, 16);
    mainLayout->setSpacing(12);
    *outLayout = mainLayout;
    return dlg;
}

/* Helper: add sorry-smiley "no data" placeholder */
static void addSorryPlaceholder(QVBoxLayout *mainLayout, QDialog *dlg, bool dark,
                                 const QString &protocolName, guint32 matchedPackets)
{
    mainLayout->addStretch(1);

    SorrySmileyWidget *smiley = new SorrySmileyWidget(dlg);
    smiley->setFixedSize(140, 140);
    QHBoxLayout *smileyRow = new QHBoxLayout;
    smileyRow->addStretch(1);
    smileyRow->addWidget(smiley);
    smileyRow->addStretch(1);
    mainLayout->addLayout(smileyRow);

    QLabel *sorryLabel = new QLabel(
        QString("No %1 protocol data found in the buffer").arg(protocolName), dlg);
    sorryLabel->setAlignment(Qt::AlignCenter);
    sorryLabel->setStyleSheet(
        QString("font-size: 16px; font-weight: bold; color: %1; padding: 12px;")
            .arg(dark ? "#e0e0e0" : "#333"));
    mainLayout->addWidget(sorryLabel);

    QString diagText = QString(
        "<div style='text-align:center; color:%1; font-size:12px; padding:8px;'>"
        "Packets matched: <b>%2</b>"
        "</div>")
        .arg(dark ? "#888" : "#999")
        .arg(matchedPackets);
    QLabel *diagLabel = new QLabel(diagText, dlg);
    diagLabel->setAlignment(Qt::AlignCenter);
    diagLabel->setTextFormat(Qt::RichText);
    mainLayout->addWidget(diagLabel);

    mainLayout->addStretch(1);
}

/* Helper: add styled QTextEdit with HTML content */
static void addHtmlTextEdit(QVBoxLayout *mainLayout, QDialog *dlg, bool dark, const QString &html)
{
    QTextEdit *textEdit = new QTextEdit(dlg);
    textEdit->setReadOnly(true);
    textEdit->setHtml(html);
    if (dark) {
        textEdit->setStyleSheet(
            "QTextEdit {"
            "  background: #1e1e1e;"
            "  color: #e0e0e0;"
            "  border: 1px solid #444;"
            "  border-radius: 4px;"
            "  padding: 8px;"
            "}");
    } else {
        textEdit->setStyleSheet(
            "QTextEdit {"
            "  background: #fafafa;"
            "  color: #222;"
            "  border: 1px solid #ccc;"
            "  border-radius: 4px;"
            "  padding: 8px;"
            "}");
    }
    mainLayout->addWidget(textEdit);
}

/* Helper: add Close button row */
static void addCloseButton(QVBoxLayout *mainLayout, QDialog *dlg, bool dark)
{
    QHBoxLayout *btnRow = new QHBoxLayout;
    btnRow->addStretch(1);
    QPushButton *closeBtn = new QPushButton("Close", dlg);
    closeBtn->setFixedWidth(100);
    if (dark) {
        closeBtn->setStyleSheet(
            "QPushButton {"
            "  background: #444; color: #e0e0e0; border: 1px solid #666;"
            "  border-radius: 4px; padding: 6px 16px; font-weight: bold;"
            "}"
            "QPushButton:hover { background: #555; }");
    } else {
        closeBtn->setStyleSheet(
            "QPushButton {"
            "  background: #e0e0e0; color: #222; border: 1px solid #aaa;"
            "  border-radius: 4px; padding: 6px 16px; font-weight: bold;"
            "}"
            "QPushButton:hover { background: #d0d0d0; }");
    }
    QObject::connect(closeBtn, &QPushButton::clicked, dlg, &QDialog::accept);
    btnRow->addWidget(closeBtn);
    btnRow->addStretch(1);
    mainLayout->addLayout(btnRow);
}

void ConnectionPopup::showSqlInfoForRow(int row)
{
    if (row < 0 || row >= m_rowData.size() || !m_pair)
        return;

    const RowData &rd = m_rowData[row];

    capture_file *cf = (capture_file *)plugin_if_get_capture_file(
        extract_capture_file, NULL);

    QString dlgTitle = sqlDialogTitle(rd.port);

    if (!cf) {
        QMessageBox::warning(this, dlgTitle,
            "No capture file is currently loaded in Wireshark.");
        return;
    }

    QString src = QString::fromUtf8(m_pair->src_addr);
    QString dst = QString::fromUtf8(m_pair->dst_addr);
    bool looksLikeMAC = (src.count(':') == 5 && dst.count(':') == 5);

    sql_info_t *sq = packet_analyzer_extract_sql_info(
        cf, m_pair->src_addr, m_pair->dst_addr,
        rd.port, looksLikeMAC ? TRUE : FALSE);

    bool dark = isDarkTheme();
    QVBoxLayout *mainLayout;
    QDialog *dlg = createInfoDialog(dlgTitle, dark, &mainLayout);

    if (!sq || !sq->found) {
        addSorryPlaceholder(mainLayout, dlg, dark,
                            sqlProtocolName(rd.port),
                            sq ? sq->matched_packets : 0);
    } else {
        QString html;
        QString headingColor = dark ? "#90caf9" : "#1565c0";
        QString textColor    = dark ? "#e0e0e0" : "#222";
        QString dimColor     = dark ? "#999"    : "#666";
        QString valColor     = dark ? "#c8e6c9" : "#1b5e20";

        html += QString("<div style='color:%1;'>").arg(textColor);

        /* ---- Connection ---- */
        html += QString("<h3 style='color:%1; margin-bottom:4px;'>Connection</h3>").arg(headingColor);
        html += QString("<table cellpadding='3'>"
                        "<tr><td style='color:%1;'>Database Type:</td>"
                        "<td><b>%2</b></td></tr>"
                        "<tr><td style='color:%1;'>Endpoints:</td>"
                        "<td><b>%3</b> &#8596; <b>%4</b></td></tr>"
                        "<tr><td style='color:%1;'>Port:</td>"
                        "<td><b>%5</b></td></tr>"
                        "<tr><td style='color:%1;'>Packets matched:</td>"
                        "<td><b>%6</b></td></tr>")
                    .arg(dimColor)
                    .arg(sq->db_type ? QString::fromUtf8(sq->db_type) : sqlProtocolName(rd.port))
                    .arg(src.toHtmlEscaped())
                    .arg(dst.toHtmlEscaped())
                    .arg(rd.port)
                    .arg(sq->matched_packets);

        if (sq->version)
            html += QString("<tr><td style='color:%1;'>Server Version:</td>"
                            "<td style='color:%2;'><b>%3</b></td></tr>")
                        .arg(dimColor).arg(valColor)
                        .arg(QString::fromUtf8(sq->version).toHtmlEscaped());
        if (sq->server_name)
            html += QString("<tr><td style='color:%1;'>Server Name:</td>"
                            "<td style='color:%2;'><b>%3</b></td></tr>")
                        .arg(dimColor).arg(valColor)
                        .arg(QString::fromUtf8(sq->server_name).toHtmlEscaped());
        html += "</table><br>";

        /* ---- Authentication ---- */
        if (sq->username || sq->database || sq->app_name || sq->client_name || sq->auth_plugin) {
            html += QString("<h3 style='color:%1; margin-bottom:4px;'>Session</h3>").arg(headingColor);
            html += "<table cellpadding='3'>";
            if (sq->username)
                html += QString("<tr><td style='color:%1;'>Username:</td>"
                                "<td style='color:%2;'><b>%3</b></td></tr>")
                            .arg(dimColor).arg(valColor)
                            .arg(QString::fromUtf8(sq->username).toHtmlEscaped());
            if (sq->database)
                html += QString("<tr><td style='color:%1;'>Database:</td>"
                                "<td style='color:%2;'><b>%3</b></td></tr>")
                            .arg(dimColor).arg(valColor)
                            .arg(QString::fromUtf8(sq->database).toHtmlEscaped());
            if (sq->app_name)
                html += QString("<tr><td style='color:%1;'>Application:</td>"
                                "<td><b>%2</b></td></tr>")
                            .arg(dimColor)
                            .arg(QString::fromUtf8(sq->app_name).toHtmlEscaped());
            if (sq->client_name)
                html += QString("<tr><td style='color:%1;'>Client Host:</td>"
                                "<td><b>%2</b></td></tr>")
                            .arg(dimColor)
                            .arg(QString::fromUtf8(sq->client_name).toHtmlEscaped());
            if (sq->auth_plugin)
                html += QString("<tr><td style='color:%1;'>Auth Method:</td>"
                                "<td><b>%2</b></td></tr>")
                            .arg(dimColor)
                            .arg(QString::fromUtf8(sq->auth_plugin).toHtmlEscaped());
            html += "</table><br>";
        }

        /* ---- Queries ---- */
        if (sq->queries) {
            html += QString("<h3 style='color:%1; margin-bottom:4px;'>Queries (%2 total)</h3>")
                        .arg(headingColor).arg(sq->query_total);
            int count = 0;
            for (GList *l = sq->queries; l; l = l->next) {
                const gchar *q = (const gchar *)l->data;
                if (!q) continue;
                count++;
                if (count > 30) {
                    guint total = g_list_length(sq->queries);
                    html += QString("<span style='color:%1;'>... and %2 more unique queries</span><br>")
                                .arg(dimColor).arg(total - 30);
                    break;
                }
                QString qStr = QString::fromUtf8(q).toHtmlEscaped();
                if (qStr.length() > 200) qStr = qStr.left(200) + "...";
                html += QString("<div style='font-family:monospace; font-size:11px; "
                                "margin:2px 0; padding:3px; background:%1; border-radius:3px;'>%2</div>")
                            .arg(dark ? "#2a2a2a" : "#f0f0f0")
                            .arg(qStr);
            }
            html += "<br>";
        }

        /* ---- Errors ---- */
        if (sq->error_messages) {
            html += QString("<h3 style='color:%1; margin-bottom:2px;'>Errors</h3>"
                            "<div style='color:%2; font-size:10px; margin-bottom:6px;'>"
                            "Server error messages found in the captured traffic</div>")
                        .arg(dark ? "#ef9a9a" : "#c62828")
                        .arg(dimColor);
            for (GList *l = sq->error_messages; l; l = l->next) {
                const gchar *e = (const gchar *)l->data;
                if (e) html += QString("&nbsp;&nbsp;&#8226; <span style='color:%1;'>%2</span><br>")
                                    .arg(dark ? "#ef9a9a" : "#c62828")
                                    .arg(QString::fromUtf8(e).toHtmlEscaped());
            }
            html += "<br>";
        }

        /* ---- PostgreSQL Parameters ---- */
        if (sq->pg_params && g_hash_table_size(sq->pg_params) > 0) {
            html += QString("<h3 style='color:%1; margin-bottom:4px;'>Server Parameters</h3>").arg(headingColor);
            html += "<table cellpadding='3'>";
            GHashTableIter iter;
            gpointer key, value;
            g_hash_table_iter_init(&iter, sq->pg_params);
            while (g_hash_table_iter_next(&iter, &key, &value)) {
                html += QString("<tr><td style='color:%1;'>%2</td>"
                                "<td style='color:%3;'><b>%4</b></td></tr>")
                            .arg(dimColor)
                            .arg(QString::fromUtf8((const gchar *)key).toHtmlEscaped())
                            .arg(valColor)
                            .arg(QString::fromUtf8((const gchar *)value).toHtmlEscaped());
            }
            html += "</table><br>";
        }

        /* ---- Command Statistics ---- */
        html += renderHashCountTable(sq->cmd_counts, headingColor, valColor, dimColor, "Commands");

        /* ---- Response Statistics ---- */
        html += renderHashCountTable(sq->response_counts, headingColor, valColor, dimColor, "Responses");

        html += "</div>";

        addHtmlTextEdit(mainLayout, dlg, dark, html);
    }

    addCloseButton(mainLayout, dlg, dark);

    packet_analyzer_free_sql_info(sq);

    /* Stop auto-close timer while dialog is open. deleteLater() AFTER exec()
     * ensures the object is not freed during the dialog's nested event loop
     * (would cause SIGSEGV if the timer also fires deleteLater mid-exec).   */
    if (m_autoCloseTimer) m_autoCloseTimer->stop();
    m_contextMenuActive = true;
    hide();
    dlg->exec();
    deleteLater();
}

/* ------------------------------------------------------------------ */
/* VoIP / SIP Information Dialog                                         */
/* ------------------------------------------------------------------ */

void ConnectionPopup::showVoipInfoForRow(int row)
{
    if (row < 0 || row >= m_rowData.size() || !m_pair)
        return;

    const RowData &rd = m_rowData[row];

    capture_file *cf = (capture_file *)plugin_if_get_capture_file(
        extract_capture_file, NULL);

    QString dlgTitle = (rd.port == 5061) ? "SIP / TLS Information" : "SIP / VoIP Information";

    if (!cf) {
        QMessageBox::warning(this, dlgTitle,
            "No capture file is currently loaded in Wireshark.");
        return;
    }

    QString src = QString::fromUtf8(m_pair->src_addr);
    QString dst = QString::fromUtf8(m_pair->dst_addr);
    bool looksLikeMAC = (src.count(':') == 5 && dst.count(':') == 5);

    voip_info_t *vi = packet_analyzer_extract_voip_info(
        cf, m_pair->src_addr, m_pair->dst_addr,
        rd.port, looksLikeMAC ? TRUE : FALSE);

    bool dark = isDarkTheme();
    QVBoxLayout *mainLayout;
    QDialog *dlg = createInfoDialog(dlgTitle, dark, &mainLayout);

    if (!vi || !vi->found) {
        addSorryPlaceholder(mainLayout, dlg, dark,
                            "SIP/VoIP",
                            vi ? vi->matched_packets : 0);
    } else {
        QString html;
        QString headingColor = dark ? "#90caf9" : "#1565c0";
        QString textColor    = dark ? "#e0e0e0" : "#222";
        QString dimColor     = dark ? "#999"    : "#666";
        QString valColor     = dark ? "#c8e6c9" : "#1b5e20";

        html += QString("<div style='color:%1;'>").arg(textColor);

        /* ---- Connection ---- */
        html += QString("<h3 style='color:%1; margin-bottom:4px;'>Connection</h3>").arg(headingColor);
        html += QString("<table cellpadding='3'>"
                        "<tr><td style='color:%1;'>Protocol:</td>"
                        "<td><b>SIP</b></td></tr>"
                        "<tr><td style='color:%1;'>Endpoints:</td>"
                        "<td><b>%2</b> &#8596; <b>%3</b></td></tr>"
                        "<tr><td style='color:%1;'>Port:</td>"
                        "<td><b>%4</b></td></tr>"
                        "<tr><td style='color:%1;'>Packets matched:</td>"
                        "<td><b>%5</b></td></tr>"
                        "</table><br>")
                    .arg(dimColor)
                    .arg(src.toHtmlEscaped())
                    .arg(dst.toHtmlEscaped())
                    .arg(rd.port)
                    .arg(vi->matched_packets);

        /* ---- Authentication ---- */
        if (vi->auth_username) {
            html += QString("<h3 style='color:%1; margin-bottom:4px;'>Authentication</h3>").arg(headingColor);
            html += QString("<table cellpadding='3'>"
                            "<tr><td style='color:%1;'>Username:</td>"
                            "<td style='color:%2;'><b>%3</b></td></tr>"
                            "</table><br>")
                        .arg(dimColor).arg(valColor)
                        .arg(QString::fromUtf8(vi->auth_username).toHtmlEscaped());
        }

        /* ---- SIP Addresses ---- */
        if (vi->from_addrs || vi->to_addrs) {
            html += QString("<h3 style='color:%1; margin-bottom:4px;'>SIP Addresses</h3>").arg(headingColor);
            html += "<table cellpadding='3'>";
            if (vi->from_addrs) {
                for (GList *l = vi->from_addrs; l; l = l->next) {
                    const gchar *a = (const gchar *)l->data;
                    if (a) html += QString("<tr><td style='color:%1;'>From:</td>"
                                           "<td style='color:%2;'><b>%3</b></td></tr>")
                                       .arg(dimColor).arg(valColor)
                                       .arg(QString::fromUtf8(a).toHtmlEscaped());
                }
            }
            if (vi->to_addrs) {
                for (GList *l = vi->to_addrs; l; l = l->next) {
                    const gchar *a = (const gchar *)l->data;
                    if (a) html += QString("<tr><td style='color:%1;'>To:</td>"
                                           "<td><b>%2</b></td></tr>")
                                       .arg(dimColor)
                                       .arg(QString::fromUtf8(a).toHtmlEscaped());
                }
            }
            html += "</table><br>";
        }

        /* ---- Call IDs ---- */
        if (vi->call_ids) {
            html += QString("<h3 style='color:%1; margin-bottom:4px;'>Call IDs (%2)</h3>")
                        .arg(headingColor).arg(g_list_length(vi->call_ids));
            int count = 0;
            for (GList *l = vi->call_ids; l; l = l->next) {
                const gchar *c = (const gchar *)l->data;
                if (!c) continue;
                count++;
                if (count > 20) {
                    guint total = g_list_length(vi->call_ids);
                    html += QString("<span style='color:%1;'>... and %2 more</span><br>")
                                .arg(dimColor).arg(total - 20);
                    break;
                }
                html += QString("&nbsp;&nbsp;&#8226; <span style='font-family:monospace; font-size:11px;'>%1</span><br>")
                            .arg(QString::fromUtf8(c).toHtmlEscaped());
            }
            html += "<br>";
        }

        /* ---- User-Agent ---- */
        if (vi->user_agents) {
            html += QString("<h3 style='color:%1; margin-bottom:4px;'>User-Agent</h3>").arg(headingColor);
            for (GList *l = vi->user_agents; l; l = l->next) {
                const gchar *ua = (const gchar *)l->data;
                if (ua) html += QString("&nbsp;&nbsp;&#8226; <span style='font-family:monospace; font-size:12px;'>%1</span><br>")
                                    .arg(QString::fromUtf8(ua).toHtmlEscaped());
            }
            html += "<br>";
        }

        /* ---- Content-Types ---- */
        if (vi->content_types) {
            html += QString("<h3 style='color:%1; margin-bottom:4px;'>Content-Types</h3>").arg(headingColor);
            for (GList *l = vi->content_types; l; l = l->next) {
                const gchar *ct = (const gchar *)l->data;
                if (ct) html += QString("&nbsp;&nbsp;&#8226; <span style='font-family:monospace; font-size:12px;'>%1</span><br>")
                                    .arg(QString::fromUtf8(ct).toHtmlEscaped());
            }
            html += "<br>";
        }

        /* ---- SIP Method Statistics ---- */
        html += renderHashCountTable(vi->method_counts, headingColor, valColor, dimColor, "SIP Methods");

        /* ---- SIP Status Code Statistics ---- */
        html += renderHashCountTable(vi->status_counts, headingColor, valColor, dimColor, "SIP Status Codes");

        /* ---- RTP Media ---- */
        if (vi->rtp_packet_count > 0 || vi->rtp_ssrcs || vi->rtp_payload_types) {
            html += QString("<h3 style='color:%1; margin-bottom:4px;'>RTP Media</h3>").arg(headingColor);
            html += "<table cellpadding='3'>";
            html += QString("<tr><td style='color:%1;'>RTP Packets:</td>"
                            "<td><b>%2</b></td></tr>")
                        .arg(dimColor).arg(vi->rtp_packet_count);

            if (vi->rtp_payload_types) {
                QString ptList;
                for (GList *l = vi->rtp_payload_types; l; l = l->next) {
                    const gchar *pt = (const gchar *)l->data;
                    if (pt) {
                        if (!ptList.isEmpty()) ptList += ", ";
                        ptList += QString::fromUtf8(pt).toHtmlEscaped();
                    }
                }
                html += QString("<tr><td style='color:%1;'>Payload Types:</td>"
                                "<td style='color:%2;'><b>%3</b></td></tr>")
                            .arg(dimColor).arg(valColor).arg(ptList);
            }

            if (vi->rtp_ssrcs) {
                html += QString("<tr><td style='color:%1;'>SSRC Count:</td>"
                                "<td><b>%2</b></td></tr>")
                            .arg(dimColor).arg(g_list_length(vi->rtp_ssrcs));
            }

            if (vi->rtp_setup_methods) {
                QString smList;
                for (GList *l = vi->rtp_setup_methods; l; l = l->next) {
                    const gchar *sm = (const gchar *)l->data;
                    if (sm) {
                        if (!smList.isEmpty()) smList += ", ";
                        smList += QString::fromUtf8(sm).toHtmlEscaped();
                    }
                }
                html += QString("<tr><td style='color:%1;'>Setup Method:</td>"
                                "<td><b>%2</b></td></tr>")
                            .arg(dimColor).arg(smList);
            }
            html += "</table><br>";

            /* List SSRCs */
            if (vi->rtp_ssrcs && g_list_length(vi->rtp_ssrcs) <= 20) {
                html += QString("<div style='margin-top:2px;'>"
                                "<span style='color:%1;'>SSRCs:</span></div>")
                            .arg(dimColor);
                for (GList *l = vi->rtp_ssrcs; l; l = l->next) {
                    const gchar *s = (const gchar *)l->data;
                    if (s) html += QString("&nbsp;&nbsp;&#8226; <span style='font-family:monospace; font-size:11px;'>%1</span><br>")
                                       .arg(QString::fromUtf8(s).toHtmlEscaped());
                }
                html += "<br>";
            }
        }

        /* ---- H.223 ---- */
        if (vi->h223_mux_count > 0) {
            html += QString("<h3 style='color:%1; margin-bottom:4px;'>H.223 Multiplexing</h3>").arg(headingColor);
            html += QString("<table cellpadding='3'>"
                            "<tr><td style='color:%1;'>MUX PDUs:</td>"
                            "<td><b>%2</b></td></tr>"
                            "</table><br>")
                        .arg(dimColor).arg(vi->h223_mux_count);
        }

        html += "</div>";

        addHtmlTextEdit(mainLayout, dlg, dark, html);
    }

    addCloseButton(mainLayout, dlg, dark);

    packet_analyzer_free_voip_info(vi);

    /* Stop auto-close timer while dialog is open. deleteLater() AFTER exec()
     * ensures the object is not freed during the dialog's nested event loop
     * (would cause SIGSEGV if the timer also fires deleteLater mid-exec).   */
    if (m_autoCloseTimer) m_autoCloseTimer->stop();
    m_contextMenuActive = true;
    hide();
    dlg->exec();
    deleteLater();
}

/* ================================================================== */
/*  Layer-2 info dialogs                                               */
/* ================================================================== */

void ConnectionPopup::showL2InfoDialog()
{
    if (!m_pair) return;

    capture_file *cf = (capture_file *)plugin_if_get_capture_file(
        extract_capture_file, NULL);

    QString dlgTitle = "Layer-2 Frame Details";

    if (!cf) {
        QMessageBox::warning(this, dlgTitle,
            "No capture file is currently loaded in Wireshark.");
        return;
    }

    l2_info_t *li = packet_analyzer_extract_l2_info(
        cf, m_pair->src_addr, m_pair->dst_addr, TRUE);

    bool dark = isDarkTheme();
    QVBoxLayout *mainLayout;
    QDialog *dlg = createInfoDialog(dlgTitle, dark, &mainLayout);

    if (!li || !li->found) {
        addSorryPlaceholder(mainLayout, dlg, dark,
                            "Layer-2",
                            li ? li->matched_packets : 0);
    } else {
        QString html;
        QString headingColor = dark ? "#90caf9" : "#1565c0";
        QString textColor    = dark ? "#e0e0e0" : "#222";
        QString dimColor     = dark ? "#999"    : "#666";
        QString valColor     = dark ? "#c8e6c9" : "#1b5e20";

        html += QString("<div style='color:%1;'>").arg(textColor);

        /* ---- EtherType Overview ---- */
        html += QString("<h3 style='color:%1; margin-bottom:4px;'>EtherTypes Observed</h3>").arg(headingColor);
        if (li->ethertype_names) {
            html += "<table cellpadding='3'>";
            for (GList *l = li->ethertype_names; l; l = l->next) {
                const gchar *et = (const gchar *)l->data;
                if (!et) continue;
                QString etStr = QString::fromUtf8(et);
                /* The hex key is the first space-delimited token */
                QString key = etStr.section(' ', 0, 0);
                gpointer pval = g_hash_table_lookup(li->ethertype_counts,
                                                    key.toUtf8().constData());
                guint cnt = pval ? GPOINTER_TO_UINT(pval) : 0;
                html += QString("<tr>"
                                "<td style='color:%1; font-family:monospace;'>%2</td>"
                                "<td style='color:%3;'><b>%4</b> frames</td>"
                                "</tr>")
                            .arg(dimColor)
                            .arg(etStr.toHtmlEscaped())
                            .arg(valColor)
                            .arg(cnt);
            }
            html += "</table><br>";
        } else {
            html += QString("<span style='color:%1;'>No EtherType data captured.</span><br><br>").arg(dimColor);
        }

        /* ---- VLAN IDs ---- */
        if (li->vlan_ids) {
            html += QString("<h3 style='color:%1; margin-bottom:4px;'>VLAN IDs</h3>").arg(headingColor);
            for (GList *l = li->vlan_ids; l; l = l->next) {
                const gchar *v = (const gchar *)l->data;
                if (v) html += QString("&nbsp;&nbsp;&#8226; <b>VLAN %1</b><br>")
                                   .arg(QString::fromUtf8(v).toHtmlEscaped());
            }
            html += "<br>";
        }

        /* ---- LLC SAPs ---- */
        if (li->llc_dsap_ssap) {
            html += QString("<h3 style='color:%1; margin-bottom:4px;'>LLC SAPs</h3>").arg(headingColor);
            for (GList *l = li->llc_dsap_ssap; l; l = l->next) {
                const gchar *s = (const gchar *)l->data;
                if (s) html += QString("&nbsp;&nbsp;&#8226; "
                                       "<span style='font-family:monospace;'>%1</span><br>")
                                   .arg(QString::fromUtf8(s).toHtmlEscaped());
            }
            html += "<br>";
        }

        /* ---- Packets matched ---- */
        html += QString("<table cellpadding='3'>"
                        "<tr><td style='color:%1;'>Packets matched:</td>"
                        "<td><b>%2</b></td></tr>"
                        "</table>")
                    .arg(dimColor).arg(li->matched_packets);

        html += "</div>";
        addHtmlTextEdit(mainLayout, dlg, dark, html);
    }

    addCloseButton(mainLayout, dlg, dark);
    packet_analyzer_free_l2_info(li);

    if (m_autoCloseTimer) m_autoCloseTimer->stop();
    m_contextMenuActive = true;
    hide();
    dlg->exec();
    deleteLater();
}

void ConnectionPopup::showStpInfoDialog()
{
    if (!m_pair) return;

    capture_file *cf = (capture_file *)plugin_if_get_capture_file(
        extract_capture_file, NULL);

    QString proto = m_pair->top_protocol ? QString::fromUtf8(m_pair->top_protocol) : "STP";
    QString dlgTitle = QString("Spanning Tree (%1) Information").arg(proto);

    if (!cf) {
        QMessageBox::warning(this, dlgTitle,
            "No capture file is currently loaded in Wireshark.");
        return;
    }

    stp_info_t *si = packet_analyzer_extract_stp_info(
        cf, m_pair->src_addr, m_pair->dst_addr, TRUE);

    bool dark = isDarkTheme();
    QVBoxLayout *mainLayout;
    QDialog *dlg = createInfoDialog(dlgTitle, dark, &mainLayout);

    if (!si || !si->found) {
        addSorryPlaceholder(mainLayout, dlg, dark,
                            "STP",
                            si ? si->matched_packets : 0);
    } else {
        QString html;
        QString headingColor = dark ? "#90caf9" : "#1565c0";
        QString textColor    = dark ? "#e0e0e0" : "#222";
        QString dimColor     = dark ? "#999"    : "#666";
        QString valColor     = dark ? "#c8e6c9" : "#1b5e20";
        QString warnColor    = dark ? "#ffb74d" : "#e65100";
        QString rootColor    = dark ? "#fff176" : "#f9a825";

        html += QString("<div style='color:%1;'>").arg(textColor);

        /* ── Section 1: Protocol ──────────────────────────────────── */
        html += QString("<h3 style='color:%1; margin-bottom:4px;'>Protocol</h3>").arg(headingColor);
        html += "<table cellpadding='3' style='border-collapse:collapse;'>";

        /* Variant */
        if (si->stp_variant)
            html += QString("<tr><td style='color:%1; white-space:nowrap;'>Variant:</td>"
                            "<td><b>%2</b></td></tr>")
                        .arg(dimColor)
                        .arg(QString::fromUtf8(si->stp_variant).toHtmlEscaped());

        /* PVST+ VLAN */
        if (si->is_pvst)
            html += QString("<tr><td style='color:%1; white-space:nowrap;'>PVST+ VLAN:</td>"
                            "<td><b>%2</b></td></tr>")
                        .arg(dimColor).arg(si->pvst_vlan);

        /* BPDU type breakdown */
        html += QString("<tr><td style='color:%1; white-space:nowrap; vertical-align:top;'>"
                        "BPDU Types:</td><td>").arg(dimColor);
        {
            QStringList bpduParts;
            if (si->config_bpdu_count > 0)
                bpduParts << QString("Config &times; %1").arg(si->config_bpdu_count);
            if (si->tcn_bpdu_count > 0)
                bpduParts << QString("TCN &times; %1").arg(si->tcn_bpdu_count);
            if (si->rst_bpdu_count > 0)
                bpduParts << QString("RST/MST &times; %1").arg(si->rst_bpdu_count);
            if (bpduParts.isEmpty())
                bpduParts << QString("Unknown &times; %1").arg(si->matched_packets);
            html += bpduParts.join("<br>");
        }
        html += QString(" <span style='color:%1;'>(%2 total)</span>").arg(dimColor).arg(si->matched_packets);
        html += "</td></tr>";

        /* Timers row — shown only when at least one timer was captured */
        {
            bool hasTimers = si->hello_time_str || si->max_age_str ||
                             si->forward_delay_str || si->msg_age_str;
            if (hasTimers) {
                html += QString("<tr><td style='color:%1; white-space:nowrap; vertical-align:top;'>"
                                "Timers (s):</td><td>").arg(dimColor);
                html += "<table cellpadding='1' style='border-collapse:collapse;'><tr>";
                auto timerCell = [&](const gchar *val, const char *label) {
                    html += QString("<td style='padding-right:14px;'>"
                                    "<div style='font-size:0.8em; color:%1;'>%2</div>"
                                    "<div><b>%3</b></div></td>")
                                .arg(dimColor).arg(label)
                                .arg(val ? QString::fromUtf8(val).toHtmlEscaped() : QString("&mdash;"));
                };
                timerCell(si->hello_time_str,    "Hello");
                timerCell(si->max_age_str,       "Max Age");
                timerCell(si->forward_delay_str, "Fwd Delay");
                timerCell(si->msg_age_str,       "Msg Age");
                html += "</tr></table></td></tr>";
            }
        }

        html += "</table><br>";

        /* ── Section 2: Root Bridge ───────────────────────────────── */
        html += QString("<h3 style='color:%1; margin-bottom:4px;'>Root Bridge</h3>").arg(headingColor);

        /* ★ Root indicator banner */
        if (si->is_root)
            html += QString("<div style='background-color:%1; color:#222; padding:3px 8px; "
                            "border-radius:4px; margin-bottom:6px; display:inline-block;'>"
                            "&#9733;&nbsp;This bridge IS the STP root</div><br>")
                        .arg(rootColor);

        html += "<table cellpadding='3' style='border-collapse:collapse;'>";

        /* Root priority (decimal + hex) */
        html += QString("<tr><td style='color:%1; white-space:nowrap;'>Priority:</td>"
                        "<td><b>%2</b>&nbsp;<span style='color:%3;'>(0x%4)</span></td></tr>")
                    .arg(dimColor)
                    .arg(si->root_bridge_priority)
                    .arg(dimColor)
                    .arg(si->root_bridge_priority, 4, 16, QChar('0'));

        /* Root system ID extension — shown only when non-zero */
        if (si->root_bridge_ext != 0)
            html += QString("<tr><td style='color:%1; white-space:nowrap;'>Sys ID Ext:</td>"
                            "<td><b>%2</b></td></tr>")
                        .arg(dimColor).arg(si->root_bridge_ext);

        /* Root MAC */
        if (si->root_bridge_mac)
            html += QString("<tr><td style='color:%1; white-space:nowrap;'>MAC:</td>"
                            "<td style='font-family:monospace; color:%2;'><b>%3</b></td></tr>")
                        .arg(dimColor).arg(valColor)
                        .arg(QString::fromUtf8(si->root_bridge_mac).toHtmlEscaped());

        /* Root path cost */
        html += QString("<tr><td style='color:%1; white-space:nowrap;'>Path Cost:</td>"
                        "<td><b>%2</b></td></tr>")
                    .arg(dimColor).arg(si->root_path_cost);

        html += "</table><br>";

        /* ── Section 3: Local Bridge ──────────────────────────────── */
        html += QString("<h3 style='color:%1; margin-bottom:4px;'>Local Bridge</h3>").arg(headingColor);
        html += "<table cellpadding='3' style='border-collapse:collapse;'>";

        /* Local priority */
        html += QString("<tr><td style='color:%1; white-space:nowrap;'>Priority:</td>"
                        "<td><b>%2</b>&nbsp;<span style='color:%3;'>(0x%4)</span></td></tr>")
                    .arg(dimColor)
                    .arg(si->bridge_priority)
                    .arg(dimColor)
                    .arg(si->bridge_priority, 4, 16, QChar('0'));

        /* Local system ID extension — shown only when non-zero */
        if (si->bridge_ext != 0)
            html += QString("<tr><td style='color:%1; white-space:nowrap;'>Sys ID Ext:</td>"
                            "<td><b>%2</b></td></tr>")
                        .arg(dimColor).arg(si->bridge_ext);

        /* Local MAC */
        if (si->bridge_mac)
            html += QString("<tr><td style='color:%1; white-space:nowrap;'>MAC:</td>"
                            "<td style='font-family:monospace;'><b>%2</b></td></tr>")
                        .arg(dimColor)
                        .arg(QString::fromUtf8(si->bridge_mac).toHtmlEscaped());

        /* Port ID: top-4-bits × 16 = port priority; bottom 12 bits = port number */
        {
            int portPriority = ((si->port_id >> 12) & 0xF) * 16;
            int portNumber   = si->port_id & 0x0FFF;
            html += QString("<tr><td style='color:%1; white-space:nowrap;'>Port ID:</td>"
                            "<td><b>0x%2</b>&nbsp;"
                            "<span style='color:%3;'>(priority %4, port %5)</span></td></tr>")
                        .arg(dimColor)
                        .arg(si->port_id, 4, 16, QChar('0'))
                        .arg(dimColor)
                        .arg(portPriority)
                        .arg(portNumber);
        }

        html += "</table><br>";

        /* ── Section 4: Port State & Flags (RSTP / MSTP / any RST flag) ── */
        {
            bool hasFlags = si->flags_proposal || si->flags_agreement ||
                            si->flags_forwarding || si->flags_learning;
            bool isRstpFamily = si->stp_variant &&
                                (g_str_has_prefix(si->stp_variant, "RSTP") ||
                                 g_str_has_prefix(si->stp_variant, "MSTP"));

            if (isRstpFamily || hasFlags || si->port_roles) {
                html += QString("<h3 style='color:%1; margin-bottom:4px;'>Port State &amp; Flags</h3>")
                            .arg(headingColor);
                html += "<table cellpadding='3' style='border-collapse:collapse;'>";

                auto flagRow = [&](const char *label, bool val) {
                    html += QString("<tr><td style='color:%1; white-space:nowrap;'>%2:</td>"
                                    "<td><b>%3</b></td></tr>")
                                .arg(dimColor).arg(label)
                                .arg(val ? QString("&#10003;") : QString("&mdash;"));
                };
                flagRow("Proposal",   si->flags_proposal);
                flagRow("Agreement",  si->flags_agreement);
                flagRow("Learning",   si->flags_learning);
                flagRow("Forwarding", si->flags_forwarding);

                html += "</table>";

                if (si->port_roles) {
                    html += QString("<div style='color:%1; margin-top:4px;'>Port roles seen:</div>").arg(dimColor);
                    for (GList *l = si->port_roles; l; l = l->next) {
                        const gchar *r = (const gchar *)l->data;
                        if (r) html += QString("&nbsp;&nbsp;&#8226; %1<br>")
                                           .arg(QString::fromUtf8(r).toHtmlEscaped());
                    }
                }
                html += "<br>";
            }
        }

        /* ── Section 5: Topology ──────────────────────────────────── */
        if (si->topology_change_count > 0 || si->flags_tca) {
            html += QString("<h3 style='color:%1; margin-bottom:4px;'>Topology</h3>").arg(headingColor);
            html += "<table cellpadding='3' style='border-collapse:collapse;'>";

            if (si->topology_change_count > 0)
                html += QString("<tr><td style='color:%1; white-space:nowrap;'>TC Events:</td>"
                                "<td><b>%2</b></td></tr>")
                            .arg(dimColor).arg(si->topology_change_count);

            if (si->flags_tca)
                html += QString("<tr><td style='color:%1; white-space:nowrap;'>TCA Seen:</td>"
                                "<td><b style='color:%2;'>&#10003;&nbsp;Yes</b></td></tr>")
                            .arg(dimColor).arg(warnColor);

            html += "</table><br>";
        }

        html += "</div>";
        addHtmlTextEdit(mainLayout, dlg, dark, html);
    }

    addCloseButton(mainLayout, dlg, dark);
    packet_analyzer_free_stp_info(si);

    if (m_autoCloseTimer) m_autoCloseTimer->stop();
    m_contextMenuActive = true;
    hide();
    dlg->exec();
    deleteLater();
}

void ConnectionPopup::showLldpInfoDialog()
{
    if (!m_pair) return;

    capture_file *cf = (capture_file *)plugin_if_get_capture_file(
        extract_capture_file, NULL);

    QString dlgTitle = "LLDP Information";

    if (!cf) {
        QMessageBox::warning(this, dlgTitle,
            "No capture file is currently loaded in Wireshark.");
        return;
    }

    lldp_info_t *li = packet_analyzer_extract_lldp_info(
        cf, m_pair->src_addr, m_pair->dst_addr, TRUE);

    bool dark = isDarkTheme();
    QVBoxLayout *mainLayout;
    QDialog *dlg = createInfoDialog(dlgTitle, dark, &mainLayout);

    if (!li || !li->found) {
        addSorryPlaceholder(mainLayout, dlg, dark,
                            "LLDP",
                            li ? li->matched_packets : 0);
    } else {
        QString html;
        QString headingColor = dark ? "#90caf9" : "#1565c0";
        QString textColor    = dark ? "#e0e0e0" : "#222";
        QString dimColor     = dark ? "#999"    : "#666";
        QString valColor     = dark ? "#c8e6c9" : "#1b5e20";

        html += QString("<div style='color:%1;'>").arg(textColor);

        /* ---- System Identity ---- */
        html += QString("<h3 style='color:%1; margin-bottom:4px;'>System Identity</h3>").arg(headingColor);
        html += "<table cellpadding='3'>";
        if (li->system_name)
            html += QString("<tr><td style='color:%1;'>System Name:</td>"
                            "<td style='color:%2;'><b>%3</b></td></tr>")
                        .arg(dimColor).arg(valColor)
                        .arg(QString::fromUtf8(li->system_name).toHtmlEscaped());
        if (li->chassis_id)
            html += QString("<tr><td style='color:%1;'>Chassis ID:</td>"
                            "<td style='font-family:monospace;'>%2</td></tr>")
                        .arg(dimColor).arg(QString::fromUtf8(li->chassis_id).toHtmlEscaped());
        if (li->port_id)
            html += QString("<tr><td style='color:%1;'>Port ID:</td>"
                            "<td>%2</td></tr>")
                        .arg(dimColor).arg(QString::fromUtf8(li->port_id).toHtmlEscaped());
        if (li->port_description)
            html += QString("<tr><td style='color:%1;'>Port Description:</td>"
                            "<td>%2</td></tr>")
                        .arg(dimColor).arg(QString::fromUtf8(li->port_description).toHtmlEscaped());
        if (li->ttl > 0)
            html += QString("<tr><td style='color:%1;'>TTL:</td>"
                            "<td><b>%2</b> seconds</td></tr>")
                        .arg(dimColor).arg(li->ttl);
        html += QString("<tr><td style='color:%1;'>Packets matched:</td>"
                        "<td><b>%2</b></td></tr>")
                    .arg(dimColor).arg(li->matched_packets);
        html += "</table><br>";

        /* ---- System Description ---- */
        if (li->system_description) {
            html += QString("<h3 style='color:%1; margin-bottom:4px;'>System Description</h3>").arg(headingColor);
            html += QString("<div style='font-family:monospace; font-size:11px; padding:4px;'>%1</div><br>")
                        .arg(QString::fromUtf8(li->system_description).toHtmlEscaped());
        }

        /* ---- Capabilities ---- */
        if (li->capabilities || li->enabled_capabilities) {
            html += QString("<h3 style='color:%1; margin-bottom:4px;'>Capabilities</h3>").arg(headingColor);
            html += "<table cellpadding='3'>";
            if (li->capabilities) {
                QString caps;
                for (GList *l = li->capabilities; l; l = l->next) {
                    const gchar *c = (const gchar *)l->data;
                    if (c) {
                        if (!caps.isEmpty()) caps += ", ";
                        caps += QString::fromUtf8(c).toHtmlEscaped();
                    }
                }
                html += QString("<tr><td style='color:%1;'>Supported:</td><td>%2</td></tr>")
                            .arg(dimColor).arg(caps);
            }
            if (li->enabled_capabilities) {
                QString ecaps;
                for (GList *l = li->enabled_capabilities; l; l = l->next) {
                    const gchar *c = (const gchar *)l->data;
                    if (c) {
                        if (!ecaps.isEmpty()) ecaps += ", ";
                        ecaps += QString::fromUtf8(c).toHtmlEscaped();
                    }
                }
                html += QString("<tr><td style='color:%1;'>Enabled:</td>"
                                "<td style='color:%2;'><b>%3</b></td></tr>")
                            .arg(dimColor).arg(valColor).arg(ecaps);
            }
            html += "</table><br>";
        }

        /* ---- Management Addresses ---- */
        if (li->management_addresses) {
            html += QString("<h3 style='color:%1; margin-bottom:4px;'>Management Addresses</h3>").arg(headingColor);
            for (GList *l = li->management_addresses; l; l = l->next) {
                const gchar *a = (const gchar *)l->data;
                if (a) html += QString("&nbsp;&nbsp;&#8226; %1<br>")
                                   .arg(QString::fromUtf8(a).toHtmlEscaped());
            }
            html += "<br>";
        }

        /* ---- VLAN Names ---- */
        if (li->vlan_names) {
            html += QString("<h3 style='color:%1; margin-bottom:4px;'>VLANs</h3>").arg(headingColor);
            for (GList *l = li->vlan_names; l; l = l->next) {
                const gchar *v = (const gchar *)l->data;
                if (v) html += QString("&nbsp;&nbsp;&#8226; %1<br>")
                                   .arg(QString::fromUtf8(v).toHtmlEscaped());
            }
        }

        html += "</div>";
        addHtmlTextEdit(mainLayout, dlg, dark, html);
    }

    addCloseButton(mainLayout, dlg, dark);
    packet_analyzer_free_lldp_info(li);

    if (m_autoCloseTimer) m_autoCloseTimer->stop();
    m_contextMenuActive = true;
    hide();
    dlg->exec();
    deleteLater();
}

void ConnectionPopup::showLacpInfoDialog()
{
    if (!m_pair) return;

    capture_file *cf = (capture_file *)plugin_if_get_capture_file(
        extract_capture_file, NULL);

    QString dlgTitle = "LACP Information";

    if (!cf) {
        QMessageBox::warning(this, dlgTitle,
            "No capture file is currently loaded in Wireshark.");
        return;
    }

    lacp_info_t *li = packet_analyzer_extract_lacp_info(
        cf, m_pair->src_addr, m_pair->dst_addr, TRUE);

    bool dark = isDarkTheme();
    QVBoxLayout *mainLayout;
    QDialog *dlg = createInfoDialog(dlgTitle, dark, &mainLayout);

    if (!li || !li->found) {
        addSorryPlaceholder(mainLayout, dlg, dark,
                            "LACP",
                            li ? li->matched_packets : 0);
    } else {
        QString html;
        QString headingColor = dark ? "#90caf9" : "#1565c0";
        QString textColor    = dark ? "#e0e0e0" : "#222";
        QString dimColor     = dark ? "#999"    : "#666";
        QString valColor     = dark ? "#c8e6c9" : "#1b5e20";

        /* Decode LACP state bitmask into human-readable flags */
        auto decodeState = [](guint8 state) -> QString {
            QStringList flags;
            if (state & 0x01) flags << "Active";
            if (state & 0x02) flags << "Short Timeout";
            if (state & 0x04) flags << "Aggregatable";
            if (state & 0x08) flags << "In Sync";
            if (state & 0x10) flags << "Collecting";
            if (state & 0x20) flags << "Distributing";
            if (state & 0x40) flags << "Defaulted";
            if (state & 0x80) flags << "Expired";
            return flags.isEmpty() ? QString("0x%1").arg(state, 2, 16, QChar('0'))
                                   : flags.join(", ");
        };

        html += QString("<div style='color:%1;'>").arg(textColor);
        html += QString("<table cellpadding='3'>"
                        "<tr><td style='color:%1;'>Packets matched:</td>"
                        "<td><b>%2</b></td></tr>"
                        "</table><br>")
                    .arg(dimColor).arg(li->matched_packets);

        /* ---- Actor ---- */
        html += QString("<h3 style='color:%1; margin-bottom:4px;'>Actor (Local)</h3>").arg(headingColor);
        html += "<table cellpadding='3'>";
        if (li->actor_system)
            html += QString("<tr><td style='color:%1;'>System:</td>"
                            "<td style='font-family:monospace; color:%2;'><b>%3</b></td></tr>")
                        .arg(dimColor).arg(valColor)
                        .arg(QString::fromUtf8(li->actor_system).toHtmlEscaped());
        html += QString("<tr><td style='color:%1;'>Key:</td><td><b>%2</b></td></tr>")
                    .arg(dimColor).arg(li->actor_key);
        html += QString("<tr><td style='color:%1;'>Port:</td><td><b>%2</b></td></tr>")
                    .arg(dimColor).arg(li->actor_port);
        html += QString("<tr><td style='color:%1;'>State:</td><td>%2</td></tr>")
                    .arg(dimColor).arg(decodeState(li->actor_state).toHtmlEscaped());
        html += "</table><br>";

        /* ---- Partner ---- */
        html += QString("<h3 style='color:%1; margin-bottom:4px;'>Partner (Remote)</h3>").arg(headingColor);
        html += "<table cellpadding='3'>";
        if (li->partner_system)
            html += QString("<tr><td style='color:%1;'>System:</td>"
                            "<td style='font-family:monospace;'>%2</td></tr>")
                        .arg(dimColor).arg(QString::fromUtf8(li->partner_system).toHtmlEscaped());
        html += QString("<tr><td style='color:%1;'>Key:</td><td><b>%2</b></td></tr>")
                    .arg(dimColor).arg(li->partner_key);
        html += QString("<tr><td style='color:%1;'>Port:</td><td><b>%2</b></td></tr>")
                    .arg(dimColor).arg(li->partner_port);
        html += QString("<tr><td style='color:%1;'>State:</td><td>%2</td></tr>")
                    .arg(dimColor).arg(decodeState(li->partner_state).toHtmlEscaped());
        html += "</table>";

        html += "</div>";
        addHtmlTextEdit(mainLayout, dlg, dark, html);
    }

    addCloseButton(mainLayout, dlg, dark);
    packet_analyzer_free_lacp_info(li);

    if (m_autoCloseTimer) m_autoCloseTimer->stop();
    m_contextMenuActive = true;
    hide();
    dlg->exec();
    deleteLater();
}

void ConnectionPopup::showEapInfoDialog()
{
    if (!m_pair) return;

    capture_file *cf = (capture_file *)plugin_if_get_capture_file(
        extract_capture_file, NULL);

    QString proto = m_pair->top_protocol ? QString::fromUtf8(m_pair->top_protocol) : "EAP";
    QString dlgTitle = "802.1X / EAP Information";

    if (!cf) {
        QMessageBox::warning(this, dlgTitle,
            "No capture file is currently loaded in Wireshark.");
        return;
    }

    eap_info_t *ei = packet_analyzer_extract_eap_info(
        cf, m_pair->src_addr, m_pair->dst_addr, TRUE);

    bool dark = isDarkTheme();
    QVBoxLayout *mainLayout;
    QDialog *dlg = createInfoDialog(dlgTitle, dark, &mainLayout);

    if (!ei || !ei->found) {
        addSorryPlaceholder(mainLayout, dlg, dark,
                            "802.1X/EAP",
                            ei ? ei->matched_packets : 0);
    } else {
        QString html;
        QString headingColor = dark ? "#90caf9" : "#1565c0";
        QString textColor    = dark ? "#e0e0e0" : "#222";
        QString dimColor     = dark ? "#999"    : "#666";
        QString valColor     = dark ? "#c8e6c9" : "#1b5e20";

        html += QString("<div style='color:%1;'>").arg(textColor);

        /* ---- Overview ---- */
        html += QString("<h3 style='color:%1; margin-bottom:4px;'>Overview</h3>").arg(headingColor);
        html += "<table cellpadding='3'>";
        html += QString("<tr><td style='color:%1;'>Packets matched:</td>"
                        "<td><b>%2</b></td></tr>")
                    .arg(dimColor).arg(ei->matched_packets);

        /* EAPOL types */
        if (ei->eapol_types) {
            QString etypes;
            for (GList *l = ei->eapol_types; l; l = l->next) {
                const gchar *t = (const gchar *)l->data;
                if (t) {
                    if (!etypes.isEmpty()) etypes += ", ";
                    etypes += QString::fromUtf8(t).toHtmlEscaped();
                }
            }
            html += QString("<tr><td style='color:%1;'>EAPOL Types:</td>"
                            "<td><b>%2</b></td></tr>")
                        .arg(dimColor).arg(etypes);
        }
        html += "</table><br>";

        /* ---- EAP Methods ---- */
        if (ei->eap_types) {
            html += QString("<h3 style='color:%1; margin-bottom:4px;'>EAP Methods</h3>").arg(headingColor);
            for (GList *l = ei->eap_types; l; l = l->next) {
                const gchar *t = (const gchar *)l->data;
                if (t) html += QString("&nbsp;&nbsp;&#8226; <b>%1</b><br>")
                                   .arg(QString::fromUtf8(t).toHtmlEscaped());
            }
            html += "<br>";
        }

        /* ---- Identities ---- */
        if (ei->identities) {
            html += QString("<h3 style='color:%1; margin-bottom:4px;'>Identities</h3>").arg(headingColor);
            for (GList *l = ei->identities; l; l = l->next) {
                const gchar *id = (const gchar *)l->data;
                if (id) html += QString("&nbsp;&nbsp;&#8226; <span style='color:%1;'><b>%2</b></span><br>")
                                    .arg(valColor)
                                    .arg(QString::fromUtf8(id).toHtmlEscaped());
            }
            html += "<br>";
        }

        /* ---- Message Counts ---- */
        html += QString("<h3 style='color:%1; margin-bottom:4px;'>Message Counts</h3>").arg(headingColor);
        html += "<table cellpadding='3'>";
        if (ei->request_count > 0)
            html += QString("<tr><td style='color:%1;'>Requests:</td>"
                            "<td><b>%2</b></td></tr>").arg(dimColor).arg(ei->request_count);
        if (ei->response_count > 0)
            html += QString("<tr><td style='color:%1;'>Responses:</td>"
                            "<td><b>%2</b></td></tr>").arg(dimColor).arg(ei->response_count);
        if (ei->success_count > 0)
            html += QString("<tr><td style='color:%1;'>Success:</td>"
                            "<td style='color:%2;'><b>%3</b></td></tr>")
                        .arg(dimColor).arg(valColor).arg(ei->success_count);
        if (ei->failure_count > 0) {
            QString failColor = dark ? "#ef9a9a" : "#b71c1c";
            html += QString("<tr><td style='color:%1;'>Failure:</td>"
                            "<td style='color:%2;'><b>%3</b></td></tr>")
                        .arg(dimColor).arg(failColor).arg(ei->failure_count);
        }
        html += "</table>";

        html += "</div>";
        addHtmlTextEdit(mainLayout, dlg, dark, html);
    }

    addCloseButton(mainLayout, dlg, dark);
    packet_analyzer_free_eap_info(ei);

    if (m_autoCloseTimer) m_autoCloseTimer->stop();
    m_contextMenuActive = true;
    hide();
    dlg->exec();
    deleteLater();
}

void ConnectionPopup::showMacsecInfoDialog()
{
    if (!m_pair) return;

    capture_file *cf = (capture_file *)plugin_if_get_capture_file(
        extract_capture_file, NULL);

    QString dlgTitle = "MACsec Information";

    if (!cf) {
        QMessageBox::warning(this, dlgTitle,
            "No capture file is currently loaded in Wireshark.");
        return;
    }

    macsec_info_t *mi = packet_analyzer_extract_macsec_info(
        cf, m_pair->src_addr, m_pair->dst_addr, TRUE);

    bool dark = isDarkTheme();
    QVBoxLayout *mainLayout;
    QDialog *dlg = createInfoDialog(dlgTitle, dark, &mainLayout);

    if (!mi || !mi->found) {
        addSorryPlaceholder(mainLayout, dlg, dark,
                            "MACsec (802.1AE)",
                            mi ? mi->matched_packets : 0);
    } else {
        QString html;
        QString headingColor = dark ? "#90caf9" : "#1565c0";
        QString textColor    = dark ? "#e0e0e0" : "#222";
        QString dimColor     = dark ? "#999"    : "#666";
        QString valColor     = dark ? "#c8e6c9" : "#1b5e20";
        QString warnColor    = dark ? "#ffcc80" : "#e65100";

        html += QString("<div style='color:%1;'>").arg(textColor);

        /* ── Overview ──────────────────────────────────────────────── */
        html += QString("<h3 style='color:%1; margin-bottom:4px;'>MACsec Overview</h3>")
                    .arg(headingColor);
        html += "<table cellpadding='3'>";
        html += QString("<tr><td style='color:%1;'>Frames matched:</td>"
                        "<td><b>%2</b></td></tr>")
                    .arg(dimColor).arg(mi->matched_packets);

        /* Show protection status clearly */
        if (mi->packet_count_protected > 0) {
            html += QString("<tr><td style='color:%1;'>SecTAG present:</td>"
                            "<td style='color:%2;'><b>%3</b> frame(s)</td></tr>")
                        .arg(dimColor).arg(valColor).arg(mi->packet_count_protected);
        } else {
            /* SecTAG fields not decoded — MACsec dissector may be disabled */
            html += QString("<tr><td colspan='2' style='color:%1; font-size:10px;'>"
                            "&#9432; SecTAG fields not decoded &mdash; enable the MACsec "
                            "dissector in Wireshark preferences if fields are missing."
                            "</td></tr>")
                        .arg(warnColor);
        }

        /* Encryption */
        html += QString("<tr><td style='color:%1;'>Encryption (E bit):</td>"
                        "<td><b>%2</b></td></tr>")
                    .arg(dimColor)
                    .arg(mi->encryption_enabled ? "Yes" : "Not detected");

        /* SCI presence */
        if (mi->sci_present)
            html += QString("<tr><td style='color:%1;'>SCI included:</td>"
                            "<td><b>Yes</b></td></tr>")
                        .arg(dimColor);

        /* TCI flags decoded from the raw byte (if captured) */
        if (mi->tci_flags != 0) {
            QStringList flags;
            if (mi->tci_flags & 0x80) flags << "V (Version bit &mdash; should be 0)";
            if (mi->tci_flags & 0x40) flags << "ES (End Station)";
            if (mi->tci_flags & 0x20) flags << "SC (SCI present)";
            if (mi->tci_flags & 0x10) flags << "SCB (Single Copy Broadcast)";
            if (mi->tci_flags & 0x08) flags << "E (Encryption enabled)";
            if (mi->tci_flags & 0x04) flags << "C (Changed text)";
            if (!flags.isEmpty())
                html += QString("<tr><td style='color:%1;'>TCI flags:</td>"
                                "<td style='font-size:10px;'>%2</td></tr>")
                            .arg(dimColor).arg(flags.join("<br>").toHtmlEscaped());
        }
        html += "</table><br>";

        /* ── Association Number distribution ───────────────────────── */
        bool hasAN = (mi->an_counts[0] || mi->an_counts[1] ||
                      mi->an_counts[2] || mi->an_counts[3]);
        if (hasAN) {
            html += QString("<h3 style='color:%1; margin-bottom:4px;'>"
                            "Association Numbers (AN)</h3>").arg(headingColor);
            html += "<table cellpadding='3'>";
            for (int i = 0; i < 4; i++) {
                if (!mi->an_counts[i]) continue;
                html += QString("<tr>"
                                "<td style='color:%1;'>AN %2:</td>"
                                "<td><b>%3</b> frame(s)</td>"
                                "</tr>")
                            .arg(dimColor).arg(i).arg(mi->an_counts[i]);
            }
            html += "</table><br>";
        }

        /* ── Packet Number range (replay-protection window) ──────── */
        if (mi->pn_valid) {
            html += QString("<h3 style='color:%1; margin-bottom:4px;'>"
                            "Packet Numbers (replay protection)</h3>").arg(headingColor);
            html += "<table cellpadding='3'>";
            html += QString("<tr><td style='color:%1;'>Min PN:</td>"
                            "<td style='font-family:monospace;'><b>%2</b></td></tr>")
                        .arg(dimColor).arg(mi->min_pn);
            html += QString("<tr><td style='color:%1;'>Max PN:</td>"
                            "<td style='font-family:monospace;'><b>%2</b></td></tr>")
                        .arg(dimColor).arg(mi->max_pn);
            if (mi->max_pn > mi->min_pn)
                html += QString("<tr><td style='color:%1;'>Range:</td>"
                                "<td><b>%2</b> sequence numbers</td></tr>")
                            .arg(dimColor).arg(mi->max_pn - mi->min_pn + 1);
            html += "</table><br>";
        }

        /* ── Secure Channel Identifiers ────────────────────────────── */
        if (mi->sci_values) {
            html += QString("<h3 style='color:%1; margin-bottom:4px;'>"
                            "Secure Channel Identifiers (SCI)</h3>").arg(headingColor);
            html += QString("<div style='font-size:10px; color:%1; margin-bottom:4px;'>"
                            "Format: MAC-address / Port-ID</div>").arg(dimColor);
            for (GList *l = mi->sci_values; l; l = l->next) {
                const gchar *s = (const gchar *)l->data;
                if (s)
                    html += QString("&nbsp;&nbsp;&#8226; "
                                    "<span style='font-family:monospace; color:%1;'>%2</span><br>")
                                .arg(valColor)
                                .arg(QString::fromUtf8(s).toHtmlEscaped());
            }
        }

        html += "</div>";
        addHtmlTextEdit(mainLayout, dlg, dark, html);
    }

    addCloseButton(mainLayout, dlg, dark);
    packet_analyzer_free_macsec_info(mi);

    if (m_autoCloseTimer) m_autoCloseTimer->stop();
    m_contextMenuActive = true;
    hide();
    dlg->exec();
    deleteLater();
}

void ConnectionPopup::showVlanInfoDialog()
{
    if (!m_pair) return;

    capture_file *cf = (capture_file *)plugin_if_get_capture_file(
        extract_capture_file, NULL);

    QString dlgTitle = "VLAN (802.1Q) Information";

    if (!cf) {
        QMessageBox::warning(this, dlgTitle,
            "No capture file is currently loaded in Wireshark.");
        return;
    }

    vlan_info_t *vi = packet_analyzer_extract_vlan_info(
        cf, m_pair->src_addr, m_pair->dst_addr, TRUE);

    bool dark = isDarkTheme();
    QVBoxLayout *mainLayout;
    QDialog *dlg = createInfoDialog(dlgTitle, dark, &mainLayout);

    if (!vi || !vi->found) {
        addSorryPlaceholder(mainLayout, dlg, dark, "VLAN (802.1Q)",
                            vi ? vi->matched_packets : 0);
    } else {
        QString html;
        QString headingColor = dark ? "#90caf9" : "#1565c0";
        QString textColor    = dark ? "#e0e0e0" : "#222";
        QString dimColor     = dark ? "#999"    : "#666";
        QString valColor     = dark ? "#c8e6c9" : "#1b5e20";
        QString warnColor    = dark ? "#ffcc80" : "#e65100";

        html += QString("<div style='color:%1;'>").arg(textColor);

        /* ── Summary ──────────────────────────────────────── */
        html += QString("<table cellpadding='3'>"
                        "<tr><td style='color:%1;'>Packets matched:</td>"
                        "<td><b>%2</b></td></tr>")
                    .arg(dimColor).arg(vi->matched_packets);
        if (vi->qinq_count > 0)
            html += QString("<tr><td style='color:%1;'>QinQ / double-tagged:</td>"
                            "<td style='color:%2;'><b>%3</b></td></tr>")
                        .arg(dimColor).arg(warnColor).arg(vi->qinq_count);
        if (vi->dei_count > 0)
            html += QString("<tr><td style='color:%1;'>DEI (drop eligible):</td>"
                            "<td><b>%2</b></td></tr>")
                        .arg(dimColor).arg(vi->dei_count);
        html += "</table><br>";

        /* ── VLAN ID Breakdown ─────────────────────────────── */
        html += QString("<h3 style='color:%1; margin-bottom:4px;'>VLAN IDs</h3>")
                    .arg(headingColor);

        /* collect and sort VLAN IDs by frame count descending */
        struct VlanEntry { QString id; guint cnt; };
        QList<VlanEntry> entries;
        GHashTableIter it;
        gpointer k, v;
        g_hash_table_iter_init(&it, vi->vlan_id_counts);
        while (g_hash_table_iter_next(&it, &k, &v)) {
            VlanEntry e;
            e.id  = QString::fromUtf8((const gchar *)k);
            e.cnt = GPOINTER_TO_UINT(v);
            entries << e;
        }
        std::sort(entries.begin(), entries.end(),
                  [](const VlanEntry &a, const VlanEntry &b) {
                      return a.cnt > b.cnt; });

        html += "<table cellpadding='3'>";
        html += QString("<tr>"
                        "<th style='color:%1; text-align:left;'>VLAN ID</th>"
                        "<th style='color:%1; text-align:right;'>Frames</th>"
                        "</tr>").arg(dimColor);
        for (const VlanEntry &e : entries) {
            html += QString("<tr>"
                            "<td style='font-family:monospace; color:%1;'><b>%2</b></td>"
                            "<td style='text-align:right;'>%3</td>"
                            "</tr>")
                        .arg(valColor)
                        .arg(e.id.toHtmlEscaped())
                        .arg(e.cnt);
        }
        html += "</table><br>";

        /* ── Priority Code Point distribution ─────────────── */
        bool hasPcp = false;
        for (int i = 0; i < 8; i++) if (vi->pcp_counts[i]) { hasPcp = true; break; }
        if (hasPcp) {
            static const char *pcp_names[8] = {
                "BE (Best Effort)",   "BK (Background)",
                "EE (Excellent Effort)", "CA (Critical Apps)",
                "VI (Video)",         "VO (Voice)",
                "IC (Internetwork Ctrl)", "NC (Network Ctrl)"
            };
            html += QString("<h3 style='color:%1; margin-bottom:4px;'>Priority (PCP)</h3>")
                        .arg(headingColor);
            html += "<table cellpadding='3'>";
            html += QString("<tr>"
                            "<th style='color:%1; text-align:left;'>PCP</th>"
                            "<th style='color:%1; text-align:left;'>Class</th>"
                            "<th style='color:%1; text-align:right;'>Frames</th>"
                            "</tr>").arg(dimColor);
            for (int i = 0; i < 8; i++) {
                if (!vi->pcp_counts[i]) continue;
                html += QString("<tr>"
                                "<td style='font-family:monospace;'><b>%1</b></td>"
                                "<td style='color:%2; font-size:10px;'>%3</td>"
                                "<td style='text-align:right;'>%4</td>"
                                "</tr>")
                            .arg(i)
                            .arg(dimColor)
                            .arg(QString::fromUtf8(pcp_names[i]).toHtmlEscaped())
                            .arg(vi->pcp_counts[i]);
            }
            html += "</table>";
        }

        html += "</div>";
        addHtmlTextEdit(mainLayout, dlg, dark, html);
    }

    addCloseButton(mainLayout, dlg, dark);
    packet_analyzer_free_vlan_info(vi);

    if (m_autoCloseTimer) m_autoCloseTimer->stop();
    m_contextMenuActive = true;
    hide();
    dlg->exec();
    deleteLater();
}

void ConnectionPopup::showArpInfoDialog()
{
    if (!m_pair) return;

    capture_file *cf = (capture_file *)plugin_if_get_capture_file(
        extract_capture_file, NULL);

    QString dlgTitle = "ARP MAC / IP Mapping";

    if (!cf) {
        QMessageBox::warning(this, dlgTitle,
            "No capture file is currently loaded in Wireshark.");
        return;
    }

    arp_info_t *ai = packet_analyzer_extract_arp_info(
        cf, m_pair->src_addr, m_pair->dst_addr, TRUE);

    bool dark = isDarkTheme();
    QVBoxLayout *mainLayout;
    QDialog *dlg = createInfoDialog(dlgTitle, dark, &mainLayout);

    if (!ai || !ai->found) {
        addSorryPlaceholder(mainLayout, dlg, dark, "ARP", ai ? ai->matched_packets : 0);
    } else {
        QString html;
        QString headingColor = dark ? "#90caf9" : "#1565c0";
        QString textColor    = dark ? "#e0e0e0" : "#222";
        QString dimColor     = dark ? "#999"    : "#666";
        QString valColor     = dark ? "#c8e6c9" : "#1b5e20";
        QString warnColor    = dark ? "#ffcc80" : "#c05800";
        QString alertColor   = dark ? "#ef9a9a" : "#b71c1c";
        QString okColor      = dark ? "#81c784" : "#2e7d32";

        html += QString("<div style='color:%1;'>").arg(textColor);

        /* ---- ARP Statistics ---- */
        html += QString("<h3 style='color:%1; margin-bottom:4px;'>ARP Statistics</h3>")
                    .arg(headingColor);
        html += "<table cellpadding='3'>";
        html += QString("<tr><td style='color:%1;'>Total ARP packets:</td>"
                        "<td><b>%2</b></td></tr>")
                    .arg(dimColor).arg(ai->matched_packets);
        html += QString("<tr><td style='color:%1;'>Requests (Who has?):</td>"
                        "<td><b>%2</b></td></tr>")
                    .arg(dimColor).arg(ai->request_count);
        html += QString("<tr><td style='color:%1;'>Replies (Is at):</td>"
                        "<td><b>%2</b></td></tr>")
                    .arg(dimColor).arg(ai->reply_count);
        if (ai->gratuitous_count > 0)
            html += QString("<tr><td style='color:%1;'>Gratuitous ARPs:</td>"
                            "<td style='color:%2;'><b>%3</b></td></tr>")
                        .arg(dimColor).arg(warnColor).arg(ai->gratuitous_count);
        html += "</table><br>";

        /* ---- MAC / IP Mappings (from replies) ---- */
        if (ai->mac_ip_mappings) {
            html += QString("<h3 style='color:%1; margin-bottom:4px;'>"
                            "MAC &rarr; IP Mappings"
                            "<span style='font-weight:normal; font-size:10px;'>"
                            " (from ARP replies)</span></h3>")
                        .arg(headingColor);
            html += "<table cellpadding='3'>";
            int count = 0;
            for (GList *l = ai->mac_ip_mappings; l; l = l->next) {
                const gchar *entry_c = (const gchar *)l->data;
                if (!entry_c) continue;
                count++;
                if (count > 50) {
                    guint total = g_list_length(ai->mac_ip_mappings);
                    html += QString("<tr><td colspan='2' style='color:%1;'>"
                                    "... and %2 more</td></tr>")
                                .arg(dimColor).arg(total - 50);
                    break;
                }
                QString entry = QString::fromUtf8(entry_c);
                qsizetype arrow = entry.indexOf(" -> ");
                if (arrow >= 0) {
                    QString mac = entry.left(static_cast<int>(arrow));
                    QString ip  = entry.mid(static_cast<int>(arrow) + 4);
                    html += QString("<tr>"
                                    "<td style='font-family:monospace; color:%1;'>%2</td>"
                                    "<td style='color:%3;'><b>%4</b></td>"
                                    "</tr>")
                                .arg(dimColor).arg(mac.toHtmlEscaped())
                                .arg(valColor).arg(ip.toHtmlEscaped());
                } else {
                    html += QString("<tr><td colspan='2' style='font-family:monospace;'>%1</td></tr>")
                                .arg(entry.toHtmlEscaped());
                }
            }
            html += "</table><br>";
        }

        /* ---- Security Analysis ---- */
        bool hasWarnings = ai->ip_conflict_warnings || ai->unsolicited_warnings;
        html += QString("<h3 style='color:%1; margin-bottom:4px;'>Security Analysis</h3>")
                    .arg(headingColor);

        if (!hasWarnings) {
            html += QString("<div style='color:%1;'>"
                            "&#10003; No ARP anomalies detected in this trace.</div>")
                        .arg(okColor);
        } else {
            if (ai->ip_conflict_warnings) {
                html += QString("<div style='color:%1; font-weight:bold; margin-top:4px;'>"
                                "&#9888; Possible ARP Cache Poisoning &mdash; IP conflicts:</div>")
                            .arg(alertColor);
                for (GList *l = ai->ip_conflict_warnings; l; l = l->next) {
                    const gchar *w = (const gchar *)l->data;
                    if (w) html += QString("<div style='color:%1; padding-left:12px; "
                                           "margin-top:2px;'>&#8226; %2</div>")
                                       .arg(alertColor)
                                       .arg(QString::fromUtf8(w).toHtmlEscaped());
                }
                html += "<br>";
            }
            if (ai->unsolicited_warnings) {
                html += QString("<div style='color:%1; font-weight:bold; margin-top:4px;'>"
                                "&#9888; Unsolicited ARP Replies (no matching request):</div>")
                            .arg(warnColor);
                for (GList *l = ai->unsolicited_warnings; l; l = l->next) {
                    const gchar *w = (const gchar *)l->data;
                    if (w) html += QString("<div style='color:%1; padding-left:12px; "
                                           "margin-top:2px;'>&#8226; %2</div>")
                                       .arg(warnColor)
                                       .arg(QString::fromUtf8(w).toHtmlEscaped());
                }
                html += QString("<div style='color:%1; font-size:10px; "
                                "padding-left:12px; margin-top:4px;'>"
                                "Note: Gratuitous ARPs are normal (sender IP == target IP). "
                                "Repeated unsolicited replies from an unexpected MAC are a "
                                "strong indicator of ARP cache poisoning.</div>")
                            .arg(dimColor);
            }
        }

        html += "</div>";
        addHtmlTextEdit(mainLayout, dlg, dark, html);
    }

    addCloseButton(mainLayout, dlg, dark);
    packet_analyzer_free_arp_info(ai);

    if (m_autoCloseTimer) m_autoCloseTimer->stop();
    m_contextMenuActive = true;
    hide();
    dlg->exec();
    deleteLater();
}

void ConnectionPopup::showDhcpInfoForRow(int row)
{
    if (row < 0 || row >= m_rowData.size() || !m_pair)
        return;

    const RowData &rd = m_rowData[row];

    capture_file *cf = (capture_file *)plugin_if_get_capture_file(
        extract_capture_file, NULL);

    QString dlgTitle = "DHCP Session Information";

    if (!cf) {
        QMessageBox::warning(this, dlgTitle,
            "No capture file is currently loaded in Wireshark.");
        return;
    }

    QString src = QString::fromUtf8(m_pair->src_addr);
    QString dst = QString::fromUtf8(m_pair->dst_addr);
    bool looksLikeMAC = (src.count(':') == 5 && dst.count(':') == 5);

    dhcp_info_t *di = packet_analyzer_extract_dhcp_info(
        cf, m_pair->src_addr, m_pair->dst_addr,
        rd.port, looksLikeMAC ? TRUE : FALSE);

    bool dark = isDarkTheme();
    QVBoxLayout *mainLayout;
    QDialog *dlg = createInfoDialog(dlgTitle, dark, &mainLayout);

    if (!di || !di->found) {
        addSorryPlaceholder(mainLayout, dlg, dark, "DHCP", di ? di->matched_packets : 0);
    } else {
        QString html;
        QString headingColor = dark ? "#90caf9" : "#1565c0";
        QString textColor    = dark ? "#e0e0e0" : "#222";
        QString dimColor     = dark ? "#999"    : "#666";
        QString valColor     = dark ? "#c8e6c9" : "#1b5e20";
        QString warnColor    = dark ? "#ffcc80" : "#c05800";
        QString alertColor   = dark ? "#ef9a9a" : "#b71c1c";

        html += QString("<div style='color:%1;'>").arg(textColor);

        /* ---- Message Type Summary ---- */
        html += QString("<h3 style='color:%1; margin-bottom:4px;'>Transaction Summary</h3>")
                    .arg(headingColor);
        html += "<table cellpadding='3'>";
        html += QString("<tr><td style='color:%1;'>Total DHCP packets:</td>"
                        "<td><b>%2</b></td></tr>")
                    .arg(dimColor).arg(di->matched_packets);

        struct { const char *label; guint32 cnt; QString color; } counts[] = {
            { "DHCPDISCOVER",           di->discover_count, textColor  },
            { "DHCPOFFER",              di->offer_count,    valColor   },
            { "DHCPREQUEST",            di->request_count,  textColor  },
            { "DHCPACK (confirmed)",    di->ack_count,      valColor   },
            { "DHCPNAK (refused)",      di->nak_count,      alertColor },
            { "DHCPRELEASE",            di->release_count,  dimColor   },
            { "DHCPDECLINE",            di->decline_count,  warnColor  },
            { "DHCPINFORM",             di->inform_count,   dimColor   },
        };
        for (int i = 0; i < 8; i++) {
            if (counts[i].cnt > 0)
                html += QString("<tr><td style='color:%1;'>%2:</td>"
                                "<td style='color:%3;'><b>%4</b></td></tr>")
                            .arg(dimColor)
                            .arg(QString::fromUtf8(counts[i].label).toHtmlEscaped())
                            .arg(counts[i].color)
                            .arg(counts[i].cnt);
        }
        html += "</table><br>";

        /* ---- Client Identity ---- */
        if (di->client_macs || di->hostnames) {
            html += QString("<h3 style='color:%1; margin-bottom:4px;'>Client</h3>")
                        .arg(headingColor);
            html += "<table cellpadding='3'>";
            for (GList *l = di->client_macs; l; l = l->next) {
                const gchar *mac = (const gchar *)l->data;
                if (mac)
                    html += QString("<tr><td style='color:%1;'>MAC:</td>"
                                    "<td style='font-family:monospace;'>%2</td></tr>")
                                .arg(dimColor).arg(QString::fromUtf8(mac).toHtmlEscaped());
            }
            for (GList *l = di->hostnames; l; l = l->next) {
                const gchar *h = (const gchar *)l->data;
                if (h)
                    html += QString("<tr><td style='color:%1;'>Hostname:</td>"
                                    "<td style='color:%2;'><b>%3</b></td></tr>")
                                .arg(dimColor).arg(valColor)
                                .arg(QString::fromUtf8(h).toHtmlEscaped());
            }
            html += "</table><br>";
        }

        /* ---- IP Address Flow ---- */
        if (di->offered_ips || di->requested_ips || di->assigned_ips) {
            html += QString("<h3 style='color:%1; margin-bottom:4px;'>IP Addresses</h3>")
                        .arg(headingColor);
            html += "<table cellpadding='3'>";
            auto listIPs = [&](GList *list, const char *label) {
                for (GList *l = list; l; l = l->next) {
                    const gchar *ip = (const gchar *)l->data;
                    if (ip)
                        html += QString("<tr><td style='color:%1;'>%2:</td>"
                                        "<td style='font-family:monospace; color:%3;'>"
                                        "<b>%4</b></td></tr>")
                                    .arg(dimColor)
                                    .arg(QString::fromUtf8(label).toHtmlEscaped())
                                    .arg(valColor)
                                    .arg(QString::fromUtf8(ip).toHtmlEscaped());
                }
            };
            listIPs(di->offered_ips,   "Offered (OFFER yiaddr)");
            listIPs(di->requested_ips, "Requested (REQUEST ciaddr)");
            listIPs(di->assigned_ips,  "Confirmed (ACK yiaddr)");
            html += "</table><br>";
        }

        /* ---- Server & Network Configuration ---- */
        if (di->server_ids || di->routers || di->dns_servers ||
            di->domain_names || di->lease_times) {
            html += QString("<h3 style='color:%1; margin-bottom:4px;'>Network Configuration"
                            "<span style='font-weight:normal; font-size:10px;'>"
                            " (from OFFER / ACK)</span></h3>")
                        .arg(headingColor);
            html += "<table cellpadding='3'>";
            auto listOpts = [&](GList *list, const char *label) {
                for (GList *l = list; l; l = l->next) {
                    const gchar *v = (const gchar *)l->data;
                    if (v)
                        html += QString("<tr><td style='color:%1;'>%2:</td>"
                                        "<td><b>%3</b></td></tr>")
                                    .arg(dimColor)
                                    .arg(QString::fromUtf8(label).toHtmlEscaped())
                                    .arg(QString::fromUtf8(v).toHtmlEscaped());
                }
            };
            listOpts(di->server_ids,   "DHCP Server");
            listOpts(di->routers,      "Default Gateway");
            listOpts(di->dns_servers,  "DNS Server");
            listOpts(di->domain_names, "Domain");
            listOpts(di->lease_times,  "Lease Time");
            html += "</table><br>";
        }

        /* ---- Options Requested by Client (option 55) ---- */
        if (di->requested_options) {
            html += QString("<h3 style='color:%1; margin-bottom:4px;'>Options Requested by Client"
                            "<span style='font-weight:normal; font-size:10px;'>"
                            " (parameter request list)</span></h3>")
                        .arg(headingColor);
            for (GList *l = di->requested_options; l; l = l->next) {
                const gchar *opt = (const gchar *)l->data;
                if (opt)
                    html += QString("&nbsp;&nbsp;&#8226; %1<br>")
                                .arg(QString::fromUtf8(opt).toHtmlEscaped());
            }
        }

        html += "</div>";
        addHtmlTextEdit(mainLayout, dlg, dark, html);
    }

    addCloseButton(mainLayout, dlg, dark);
    packet_analyzer_free_dhcp_info(di);

    if (m_autoCloseTimer) m_autoCloseTimer->stop();
    m_contextMenuActive = true;
    hide();
    dlg->exec();
    deleteLater();
}

/* ── DNS Query / Response Information dialog ───────────────────────────── */
void ConnectionPopup::showDnsInfoForRow(int row)
{
    if (row < 0 || row >= m_rowData.size() || !m_pair)
        return;

    const RowData &rd = m_rowData[row];

    capture_file *cf = (capture_file *)plugin_if_get_capture_file(
        extract_capture_file, NULL);

    QString src = QString::fromUtf8(m_pair->src_addr);
    QString dst = QString::fromUtf8(m_pair->dst_addr);
    QString dlgTitle = QString("DNS Information  &mdash;  %1 &#x2194; %2  (port %3)")
                           .arg(src).arg(dst).arg(rd.port);

    if (!cf) {
        QMessageBox::warning(this, dlgTitle,
            "No capture file is currently loaded in Wireshark.");
        return;
    }

    bool looksLikeMAC = (src.count(':') == 5 && dst.count(':') == 5);

    dns_info_t *di = packet_analyzer_extract_dns_info(
        cf, m_pair->src_addr, m_pair->dst_addr,
        (guint16)rd.port, looksLikeMAC ? TRUE : FALSE);

    bool dark = isDarkTheme();
    QVBoxLayout *mainLayout;
    QDialog *dlg = createInfoDialog(dlgTitle, dark, &mainLayout);

    if (!di || !di->found) {
        addSorryPlaceholder(mainLayout, dlg, dark, "DNS", di ? di->matched_packets : 0);
    } else {
        QString html;
        QString headingColor = dark ? "#90caf9" : "#1565c0";
        QString textColor    = dark ? "#e0e0e0" : "#222";
        QString dimColor     = dark ? "#999"    : "#666";
        QString valColor     = dark ? "#c8e6c9" : "#1b5e20";
        QString warnColor    = dark ? "#ffcc80" : "#c05800";
        QString alertColor   = dark ? "#ef9a9a" : "#b71c1c";
        QString monoStyle    = "font-family:monospace;";

        html += QString("<div style='color:%1;'>").arg(textColor);

        /* ── Section 1: Traffic Summary ─────────────────────────── */
        html += QString("<h3 style='color:%1; margin-bottom:4px;'>Traffic Summary</h3>")
                    .arg(headingColor);
        html += "<table cellpadding='3'>";
        html += QString("<tr><td style='color:%1;'>Total DNS packets:</td>"
                        "<td><b>%2</b></td></tr>")
                    .arg(dimColor).arg(di->matched_packets);
        html += QString("<tr><td style='color:%1;'>Queries&nbsp;&nbsp;(QR=0):</td>"
                        "<td><b>%2</b></td></tr>")
                    .arg(dimColor).arg(di->query_count);
        html += QString("<tr><td style='color:%1;'>Responses (QR=1):</td>"
                        "<td><b>%2</b></td></tr>")
                    .arg(dimColor).arg(di->response_count);
        if (di->uses_recursion)
            html += QString("<tr><td style='color:%1;'>Recursion desired:</td>"
                            "<td style='color:%2;'>Yes (RD bit set)</td></tr>")
                        .arg(dimColor).arg(valColor);
        if (di->uses_tcp)
            html += QString("<tr><td style='color:%1;'>Transport:</td>"
                            "<td style='color:%2;'>DNS-over-TCP seen</td></tr>")
                        .arg(dimColor).arg(warnColor);
        html += "</table><br>";

        /* ── Section 2: Response Codes ──────────────────────────── */
        bool hasErrors = di->nxdomain_count || di->servfail_count ||
                         di->refused_count  || di->other_error_count;
        html += QString("<h3 style='color:%1; margin-bottom:4px;'>Response Codes</h3>")
                    .arg(headingColor);
        html += "<table cellpadding='3'>";
        if (di->noerror_count)
            html += QString("<tr><td style='color:%1;'>NOERROR:</td>"
                            "<td style='color:%2;'><b>%3</b></td></tr>")
                        .arg(dimColor).arg(valColor).arg(di->noerror_count);
        if (di->nxdomain_count)
            html += QString("<tr><td style='color:%1;'>NXDOMAIN"
                            "<span style='font-size:10px;'> (domain not found)</span>:</td>"
                            "<td style='color:%2;'><b>%3</b></td></tr>")
                        .arg(dimColor).arg(warnColor).arg(di->nxdomain_count);
        if (di->servfail_count)
            html += QString("<tr><td style='color:%1;'>SERVFAIL:</td>"
                            "<td style='color:%2;'><b>%3</b></td></tr>")
                        .arg(dimColor).arg(alertColor).arg(di->servfail_count);
        if (di->refused_count)
            html += QString("<tr><td style='color:%1;'>REFUSED:</td>"
                            "<td style='color:%2;'><b>%3</b></td></tr>")
                        .arg(dimColor).arg(alertColor).arg(di->refused_count);
        if (di->other_error_count)
            html += QString("<tr><td style='color:%1;'>Other errors:</td>"
                            "<td style='color:%2;'><b>%3</b></td></tr>")
                        .arg(dimColor).arg(alertColor).arg(di->other_error_count);
        if (!di->noerror_count && !hasErrors)
            html += QString("<tr><td colspan='2' style='color:%1;'>"
                            "(no response codes observed)</td></tr>")
                        .arg(dimColor);
        html += "</table><br>";

        /* ── Section 3: Query Types ─────────────────────────────── */
        if (di->type_counts && g_hash_table_size(di->type_counts) > 0) {
            html += QString("<h3 style='color:%1; margin-bottom:4px;'>Query Types</h3>")
                        .arg(headingColor);
            html += "<table cellpadding='3'>";

            struct DnsTypeRow { QString name; guint count; };
            QVector<DnsTypeRow> typeRows;
            GHashTableIter iter;
            gpointer k, v;
            g_hash_table_iter_init(&iter, di->type_counts);
            while (g_hash_table_iter_next(&iter, &k, &v))
                typeRows.append({ QString::fromUtf8((const gchar *)k), *(const guint *)v });
            std::sort(typeRows.begin(), typeRows.end(),
                [](const DnsTypeRow &a, const DnsTypeRow &b){ return a.count > b.count; });

            for (const auto &r : typeRows)
                html += QString("<tr>"
                                "<td style='%1 color:%2; padding-right:12px;'>%3</td>"
                                "<td><b>%4</b></td></tr>")
                            .arg(monoStyle).arg(dimColor)
                            .arg(r.name.toHtmlEscaped()).arg(r.count);
            html += "</table><br>";
        }

        /* ── Section 4: Queried Domain Names ───────────────────── */
        if (di->name_counts && g_hash_table_size(di->name_counts) > 0) {
            guint totalNames = g_hash_table_size(di->name_counts);
            html += QString("<h3 style='color:%1; margin-bottom:4px;'>Queried Domains"
                            "<span style='font-weight:normal; font-size:10px;'>"
                            " (%2 unique)</span></h3>")
                        .arg(headingColor).arg(totalNames);
            html += "<table cellpadding='3'>";

            struct DnsNameRow { QString name; guint count; };
            QVector<DnsNameRow> nameRows;
            GHashTableIter niter;
            gpointer nk, nv;
            g_hash_table_iter_init(&niter, di->name_counts);
            while (g_hash_table_iter_next(&niter, &nk, &nv))
                nameRows.append({ QString::fromUtf8((const gchar *)nk), *(const guint *)nv });
            std::sort(nameRows.begin(), nameRows.end(),
                [](const DnsNameRow &a, const DnsNameRow &b){ return a.count > b.count; });

            int shown = 0;
            for (const auto &r : nameRows) {
                if (shown >= 60) {
                    html += QString("<tr><td colspan='2' style='color:%1;'>"
                                    "&hellip; and %2 more</td></tr>")
                                .arg(dimColor).arg((int)nameRows.size() - shown);
                    break;
                }
                html += QString("<tr>"
                                "<td style='%1 color:%2;'>%3</td>"
                                "<td style='color:%4; padding-left:8px;'>&times;%5</td>"
                                "</tr>")
                            .arg(monoStyle).arg(textColor)
                            .arg(r.name.toHtmlEscaped())
                            .arg(r.count > 1 ? warnColor : dimColor)
                            .arg(r.count);
                shown++;
            }
            html += "</table><br>";
        }

        /* ── Section 5: Resolved Answers ───────────────────────── */
        if (di->answers) {
            guint totalAnswers = g_list_length(di->answers);
            html += QString("<h3 style='color:%1; margin-bottom:4px;'>Resolved Answers"
                            "<span style='font-weight:normal; font-size:10px;'>"
                            " (%2 unique)</span></h3>")
                        .arg(headingColor).arg(totalAnswers);
            html += "<table cellpadding='3'>";
            int count = 0;
            for (GList *l = di->answers; l; l = l->next) {
                const gchar *entry_c = (const gchar *)l->data;
                if (!entry_c) continue;
                count++;
                if (count > 80) {
                    html += QString("<tr><td colspan='3' style='color:%1;'>"
                                    "&hellip; and %2 more</td></tr>")
                                .arg(dimColor).arg(totalAnswers - 80);
                    break;
                }
                /* entry format: "name TYPE value" */
                QString entry = QString::fromUtf8(entry_c);
                int sp1 = entry.indexOf(' ');
                int sp2 = (sp1 >= 0) ? entry.indexOf(' ', sp1 + 1) : -1;
                if (sp1 > 0 && sp2 > sp1) {
                    QString dname = entry.left(sp1);
                    QString dtype = entry.mid(sp1 + 1, sp2 - sp1 - 1);
                    QString dval  = entry.mid(sp2 + 1);
                    html += QString("<tr>"
                                    "<td style='%1 color:%2;'>%3</td>"
                                    "<td style='color:%4; padding:0 8px;'>%5</td>"
                                    "<td style='%1 color:%6;'><b>%7</b></td>"
                                    "</tr>")
                                .arg(monoStyle).arg(dimColor).arg(dname.toHtmlEscaped())
                                .arg(warnColor).arg(dtype.toHtmlEscaped())
                                .arg(valColor).arg(dval.toHtmlEscaped());
                } else {
                    html += QString("<tr><td colspan='3' style='%1'>%2</td></tr>")
                                .arg(monoStyle).arg(entry.toHtmlEscaped());
                }
            }
            html += "</table><br>";
        }

        /* ── Section 6: NXDOMAIN Names ─────────────────────────── */
        if (di->nxdomain_names) {
            html += QString("<h3 style='color:%1; margin-bottom:4px;'>"
                            "NXDOMAIN &mdash; Domains Not Found</h3>")
                        .arg(headingColor);
            html += QString("<div style='font-size:10px; color:%1; margin-bottom:6px;'>"
                            "&#9888;&nbsp;These names returned NXDOMAIN (non-existent domain). "
                            "May indicate misconfiguration, broken links, or "
                            "DGA/C2 beacon activity worth investigating.</div>")
                        .arg(warnColor);
            int nxcount = 0;
            for (GList *l = di->nxdomain_names; l; l = l->next) {
                const gchar *nm = (const gchar *)l->data;
                if (!nm) continue;
                nxcount++;
                if (nxcount > 30) {
                    guint total = g_list_length(di->nxdomain_names);
                    html += QString("<div style='color:%1;'>&hellip; and %2 more</div>")
                                .arg(dimColor).arg(total - 30);
                    break;
                }
                html += QString("<div style='%1 color:%2; padding-left:8px;'>"
                                "&#8226;&nbsp;%3</div>")
                            .arg(monoStyle).arg(warnColor)
                            .arg(QString::fromUtf8(nm).toHtmlEscaped());
            }
            html += "<br>";
        }

        html += "</div>";
        addHtmlTextEdit(mainLayout, dlg, dark, html);
    }

    addCloseButton(mainLayout, dlg, dark);
    packet_analyzer_free_dns_info(di);

    if (m_autoCloseTimer) m_autoCloseTimer->stop();
    m_contextMenuActive = true;
    hide();
    dlg->exec();
    deleteLater();
}

/* ── LDAP Session Information dialog ───────────────────────────────────── */
void ConnectionPopup::showLdapInfoForRow(int row)
{
    if (row < 0 || row >= m_rowData.size() || !m_pair)
        return;

    const RowData &rd = m_rowData[row];

    capture_file *cf = (capture_file *)plugin_if_get_capture_file(
        extract_capture_file, NULL);

    QString src = QString::fromUtf8(m_pair->src_addr);
    QString dst = QString::fromUtf8(m_pair->dst_addr);

    /* Friendly port label */
    QString portLabel;
    switch (rd.port) {
        case  389: portLabel = "LDAP";          break;
        case  636: portLabel = "LDAPS";         break;
        case 3268: portLabel = "Global Catalog"; break;
        case 3269: portLabel = "GC / TLS";      break;
        default:   portLabel = QString("port %1").arg(rd.port); break;
    }

    QString dlgTitle = QString("LDAP Information  \u2014  %1 \u2194 %2  (%3)")
                           .arg(src, dst, portLabel);

    if (!cf) {
        QMessageBox::warning(this, dlgTitle,
            "No capture file is currently loaded in Wireshark.");
        return;
    }

    bool looksLikeMAC = (src.count(':') == 5 && dst.count(':') == 5);

    ldap_info_t *li = packet_analyzer_extract_ldap_info(
        cf, m_pair->src_addr, m_pair->dst_addr,
        (guint16)rd.port, looksLikeMAC ? TRUE : FALSE);

    bool dark = isDarkTheme();
    QVBoxLayout *mainLayout;
    QDialog *dlg = createInfoDialog(dlgTitle, dark, &mainLayout);

    if (!li || !li->found) {
        QString note;
        if (li && li->is_tls)
            note = " (traffic may be TLS-encrypted &mdash; no plaintext LDAP fields visible)";
        addSorryPlaceholder(mainLayout, dlg, dark,
                            QString("LDAP") + note,
                            li ? li->matched_packets : 0);
    } else {
        QString html;
        QString headingColor = dark ? "#90caf9" : "#1565c0";
        QString textColor    = dark ? "#e0e0e0" : "#222";
        QString dimColor     = dark ? "#999"    : "#666";
        QString valColor     = dark ? "#c8e6c9" : "#1b5e20";
        QString warnColor    = dark ? "#ffcc80" : "#c05800";
        QString alertColor   = dark ? "#ef9a9a" : "#b71c1c";
        QString monoStyle    = "font-family:monospace;";

        html += QString("<div style='color:%1;'>").arg(textColor);

        /* ── Section 1: Session Summary ─────────────────────────── */
        html += QString("<h3 style='color:%1; margin-bottom:4px;'>Session Summary</h3>")
                    .arg(headingColor);
        html += "<table cellpadding='3'>";
        html += QString("<tr><td style='color:%1;'>Protocol:</td>"
                        "<td><b>%2</b></td></tr>")
                    .arg(dimColor, portLabel);
        if (li->is_tls)
            html += QString("<tr><td style='color:%1;'>Transport security:</td>"
                            "<td style='color:%2;'>TLS encrypted</td></tr>")
                        .arg(dimColor, valColor);
        html += QString("<tr><td style='color:%1;'>Total LDAP frames:</td>"
                        "<td><b>%2</b></td></tr>")
                    .arg(dimColor).arg(li->matched_packets);
        if (li->bind_count)
            html += QString("<tr><td style='color:%1;'>Bind operations:</td>"
                            "<td><b>%2</b></td></tr>")
                        .arg(dimColor).arg(li->bind_count);
        if (li->search_count)
            html += QString("<tr><td style='color:%1;'>Search requests:</td>"
                            "<td><b>%2</b></td></tr>")
                        .arg(dimColor).arg(li->search_count);
        if (li->search_res_entry_count)
            html += QString("<tr><td style='color:%1;'>Entries returned:</td>"
                            "<td><b>%2</b></td></tr>")
                        .arg(dimColor).arg(li->search_res_entry_count);
        if (li->modify_count)
            html += QString("<tr><td style='color:%1;'>Modify operations:</td>"
                            "<td><b>%2</b></td></tr>")
                        .arg(dimColor).arg(li->modify_count);
        if (li->add_count)
            html += QString("<tr><td style='color:%1;'>Add operations:</td>"
                            "<td><b>%2</b></td></tr>")
                        .arg(dimColor).arg(li->add_count);
        if (li->delete_count)
            html += QString("<tr><td style='color:%1;'>Delete operations:</td>"
                            "<td style='color:%2;'><b>%3</b></td></tr>")
                        .arg(dimColor, warnColor).arg(li->delete_count);
        html += "</table><br>";

        /* ── Section 2: Authentication ──────────────────────────── */
        if (li->bind_count > 0) {
            html += QString("<h3 style='color:%1; margin-bottom:4px;'>Authentication</h3>")
                        .arg(headingColor);
            html += "<table cellpadding='3'>";

            if (li->has_simple_bind && li->has_anonymous_bind)
                html += QString("<tr><td style='color:%1;'>Auth type:</td>"
                                "<td>Simple &amp; Anonymous</td></tr>")
                            .arg(dimColor);
            else if (li->has_anonymous_bind)
                html += QString("<tr><td style='color:%1;'>Auth type:</td>"
                                "<td style='color:%2;'>Anonymous bind</td></tr>")
                            .arg(dimColor, warnColor);
            else if (li->has_simple_bind)
                html += QString("<tr><td style='color:%1;'>Auth type:</td>"
                                "<td>Simple</td></tr>")
                            .arg(dimColor);
            if (li->has_sasl_bind)
                html += QString("<tr><td style='color:%1;'>Auth type:</td>"
                                "<td style='color:%2;'>SASL</td></tr>")
                            .arg(dimColor, valColor);

            /* SASL mechanisms */
            if (li->sasl_mechanisms) {
                html += QString("<tr><td style='color:%1; vertical-align:top;'>"
                                "SASL mechanisms:</td><td>").arg(dimColor);
                for (GList *l = li->sasl_mechanisms; l; l = l->next) {
                    if (l != li->sasl_mechanisms) html += ", ";
                    html += QString("<b style='%1'>%2</b>")
                                .arg(monoStyle,
                                     QString::fromUtf8((const gchar *)l->data)
                                     .toHtmlEscaped());
                }
                html += "</td></tr>";
            }

            /* Bind DNs */
            if (li->bind_dns) {
                html += "</table><br>";
                html += QString("<h3 style='color:%1; margin-bottom:4px;'>Bind DNs</h3>")
                            .arg(headingColor);
                html += "<table cellpadding='3'>";
                int shown = 0;
                for (GList *l = li->bind_dns; l; l = l->next) {
                    if (shown >= 20) {
                        html += QString("<tr><td colspan='2' style='color:%1;'>"
                                        "&hellip; and %2 more</td></tr>")
                                    .arg(dimColor)
                                    .arg((int)g_list_length(li->bind_dns) - shown);
                        break;
                    }
                    html += QString("<tr><td style='%1 color:%2;'>%3</td></tr>")
                                .arg(monoStyle, textColor,
                                     QString::fromUtf8((const gchar *)l->data)
                                     .toHtmlEscaped());
                    shown++;
                }
            }
            html += "</table><br>";
        }

        /* ── Section 3: Search Bases ────────────────────────────── */
        if (li->base_dns) {
            html += QString("<h3 style='color:%1; margin-bottom:4px;'>Search Bases</h3>")
                        .arg(headingColor);
            html += "<table cellpadding='3'>";
            int shown = 0;
            for (GList *l = li->base_dns; l; l = l->next) {
                if (shown >= 25) {
                    html += QString("<tr><td style='color:%1;'>&hellip; and %2 more</td></tr>")
                                .arg(dimColor)
                                .arg((int)g_list_length(li->base_dns) - shown);
                    break;
                }
                html += QString("<tr><td style='%1 color:%2;'>%3</td></tr>")
                            .arg(monoStyle, textColor,
                                 QString::fromUtf8((const gchar *)l->data).toHtmlEscaped());
                shown++;
            }
            html += "</table><br>";
        }

        /* ── Section 4: Search Filters ──────────────────────────── */
        if (li->search_filters) {
            guint total = g_list_length(li->search_filters);
            html += QString("<h3 style='color:%1; margin-bottom:4px;'>Search Filters"
                            "<span style='font-weight:normal; font-size:10px;'>"
                            " (%2 unique)</span></h3>")
                        .arg(headingColor).arg(total);
            html += "<table cellpadding='3'>";
            int shown = 0;
            for (GList *l = li->search_filters; l; l = l->next) {
                if (shown >= 30) {
                    html += QString("<tr><td style='color:%1;'>"
                                    "&hellip; and %2 more</td></tr>")
                                .arg(dimColor).arg(total - 30);
                    break;
                }
                html += QString("<tr><td style='%1 color:%2;'>%3</td></tr>")
                            .arg(monoStyle, dimColor,
                                 QString::fromUtf8((const gchar *)l->data).toHtmlEscaped());
                shown++;
            }
            html += "</table><br>";
        }

        /* ── Section 5: Result Codes ────────────────────────────── */
        if (li->result_counts && g_hash_table_size(li->result_counts) > 0) {
            html += QString("<h3 style='color:%1; margin-bottom:4px;'>Result Codes</h3>")
                        .arg(headingColor);
            html += "<table cellpadding='3'>";

            struct RcRow { QString name; guint count; };
            QVector<RcRow> rows;
            GHashTableIter iter;
            gpointer k, v;
            g_hash_table_iter_init(&iter, li->result_counts);
            while (g_hash_table_iter_next(&iter, &k, &v))
                rows.append({ QString::fromUtf8((const gchar *)k), *(const guint *)v });
            std::sort(rows.begin(), rows.end(),
                [](const RcRow &a, const RcRow &b){ return a.count > b.count; });

            for (const auto &r : rows) {
                bool isSuccess = (r.name == "success");
                bool isCrit    = r.name.contains("Credentials") ||
                                 r.name.contains("Access")      ||
                                 r.name.contains("Anonymous");
                QString color  = isSuccess ? valColor
                               : isCrit    ? alertColor
                               :             warnColor;
                html += QString("<tr>"
                                "<td style='%1 color:%2; padding-right:12px;'>%3</td>"
                                "<td style='color:%4;'><b>%5</b></td>"
                                "</tr>")
                            .arg(monoStyle, dimColor, r.name.toHtmlEscaped(),
                                 color).arg(r.count);
            }
            html += "</table><br>";
        }

        html += "</div>";
        addHtmlTextEdit(mainLayout, dlg, dark, html);
    }

    addCloseButton(mainLayout, dlg, dark);
    packet_analyzer_free_ldap_info(li);

    if (m_autoCloseTimer) m_autoCloseTimer->stop();
    m_contextMenuActive = true;
    hide();
    dlg->exec();
    deleteLater();
}

/* ── SNMP Session Information dialog ───────────────────────────────────── */
void ConnectionPopup::showSnmpInfoForRow(int row)
{
    if (row < 0 || row >= m_rowData.size() || !m_pair)
        return;

    const RowData &rd = m_rowData[row];

    capture_file *cf = (capture_file *)plugin_if_get_capture_file(
        extract_capture_file, NULL);

    QString src = QString::fromUtf8(m_pair->src_addr);
    QString dst = QString::fromUtf8(m_pair->dst_addr);
    QString portLabel = (rd.port == 162) ? "SNMP Traps" : "SNMP";
    QString dlgTitle  = QString("SNMP Information  \u2014  %1 \u2194 %2  (port %3)")
                            .arg(src, dst).arg(rd.port);

    if (!cf) {
        QMessageBox::warning(this, dlgTitle,
            "No capture file is currently loaded in Wireshark.");
        return;
    }

    bool looksLikeMAC = (src.count(':') == 5 && dst.count(':') == 5);

    snmp_info_t *si = packet_analyzer_extract_snmp_info(
        cf, m_pair->src_addr, m_pair->dst_addr,
        (guint16)rd.port, looksLikeMAC ? TRUE : FALSE);

    bool dark = isDarkTheme();
    QVBoxLayout *mainLayout;
    QDialog *dlg = createInfoDialog(dlgTitle, dark, &mainLayout);

    if (!si || !si->found) {
        addSorryPlaceholder(mainLayout, dlg, dark, "SNMP", si ? si->matched_packets : 0);
    } else {
        QString html;
        QString headingColor = dark ? "#90caf9" : "#1565c0";
        QString textColor    = dark ? "#e0e0e0" : "#222";
        QString dimColor     = dark ? "#999"    : "#666";
        QString valColor     = dark ? "#c8e6c9" : "#1b5e20";
        QString warnColor    = dark ? "#ffcc80" : "#c05800";
        QString alertColor   = dark ? "#ef9a9a" : "#b71c1c";
        QString monoStyle    = "font-family:monospace;";

        html += QString("<div style='color:%1;'>").arg(textColor);

        /* ── Section 1: Session Summary ─────────────────────────── */
        html += QString("<h3 style='color:%1; margin-bottom:4px;'>Session Summary</h3>")
                    .arg(headingColor);
        html += "<table cellpadding='3'>";
        html += QString("<tr><td style='color:%1;'>Total SNMP frames:</td>"
                        "<td><b>%2</b></td></tr>")
                    .arg(dimColor).arg(si->matched_packets);

        /* Version breakdown */
        if (si->v1_count)
            html += QString("<tr><td style='color:%1;'>SNMPv1:</td>"
                            "<td><b>%2</b></td></tr>").arg(dimColor).arg(si->v1_count);
        if (si->v2c_count)
            html += QString("<tr><td style='color:%1;'>SNMPv2c:</td>"
                            "<td><b>%2</b></td></tr>").arg(dimColor).arg(si->v2c_count);
        if (si->v3_count)
            html += QString("<tr><td style='color:%1;'>SNMPv3:</td>"
                            "<td style='color:%2;'><b>%3</b></td></tr>")
                        .arg(dimColor, valColor).arg(si->v3_count);
        html += "</table><br>";

        /* ── Section 2: PDU Types ───────────────────────────────── */
        if (si->pdu_counts && g_hash_table_size(si->pdu_counts) > 0) {
            html += QString("<h3 style='color:%1; margin-bottom:4px;'>PDU Operations</h3>")
                        .arg(headingColor);
            html += "<table cellpadding='3'>";

            struct PduRow { QString name; guint count; };
            QVector<PduRow> prows;
            GHashTableIter iter;
            gpointer k, v;
            g_hash_table_iter_init(&iter, si->pdu_counts);
            while (g_hash_table_iter_next(&iter, &k, &v))
                prows.append({ QString::fromUtf8((const gchar *)k), *(const guint *)v });
            std::sort(prows.begin(), prows.end(),
                [](const PduRow &a, const PduRow &b){ return a.count > b.count; });

            for (const auto &r : prows) {
                bool isSet  = r.name.startsWith("Set");
                bool isTrap = r.name.startsWith("Trap");
                QString color = isSet  ? warnColor
                              : isTrap ? alertColor
                              :          textColor;
                html += QString("<tr>"
                                "<td style='%1 color:%2; padding-right:12px;'>%3</td>"
                                "<td style='color:%4;'><b>%5</b></td>"
                                "</tr>")
                            .arg(monoStyle, dimColor, r.name.toHtmlEscaped(),
                                 color).arg(r.count);
            }
            html += "</table><br>";
        }

        /* ── Section 3: Community Strings (v1/v2c) ──────────────── */
        if (si->communities) {
            html += QString("<h3 style='color:%1; margin-bottom:4px;'>"
                            "Community Strings"
                            "<span style='font-weight:normal; font-size:10px;'>"
                            " (v1/v2c authentication)</span></h3>")
                        .arg(headingColor);
            if (si->has_default_community)
                html += QString("<div style='color:%1; font-size:10px; margin-bottom:4px;'>"
                                "&#9888;&nbsp;Default community detected ("
                                "<b>public</b> / <b>private</b>). "
                                "These are well-known defaults and indicate weak security.</div>")
                            .arg(alertColor);
            html += "<table cellpadding='3'>";
            int shown = 0;
            for (GList *l = si->communities; l; l = l->next) {
                if (shown >= 20) {
                    html += QString("<tr><td style='color:%1;'>&hellip; and more</td></tr>")
                                .arg(dimColor);
                    break;
                }
                const gchar *cs = (const gchar *)l->data;
                bool isDefault = (g_strcmp0(cs, "public") == 0 ||
                                  g_strcmp0(cs, "private") == 0);
                html += QString("<tr><td style='%1 color:%2;'>%3</td></tr>")
                            .arg(monoStyle,
                                 isDefault ? alertColor : textColor,
                                 QString::fromUtf8(cs).toHtmlEscaped());
                shown++;
            }
            html += "</table><br>";
        }

        /* ── Section 4: SNMPv3 Users ────────────────────────────── */
        if (si->v3_usernames) {
            html += QString("<h3 style='color:%1; margin-bottom:4px;'>SNMPv3 Users</h3>")
                        .arg(headingColor);
            html += "<table cellpadding='3'>";
            for (GList *l = si->v3_usernames; l; l = l->next)
                html += QString("<tr><td style='%1 color:%2;'>%3</td></tr>")
                            .arg(monoStyle, valColor,
                                 QString::fromUtf8((const gchar *)l->data).toHtmlEscaped());
            html += "</table><br>";
        }

        /* ── Section 5: Top OIDs ────────────────────────────────── */
        if (si->oid_counts && g_hash_table_size(si->oid_counts) > 0) {
            guint totalOids = g_hash_table_size(si->oid_counts);
            html += QString("<h3 style='color:%1; margin-bottom:4px;'>Variable Bindings"
                            "<span style='font-weight:normal; font-size:10px;'>"
                            " (%2 unique OIDs)</span></h3>")
                        .arg(headingColor).arg(totalOids);

            struct OidRow { QString name; guint count; };
            QVector<OidRow> orows;
            GHashTableIter oiter;
            gpointer ok, ov;
            g_hash_table_iter_init(&oiter, si->oid_counts);
            while (g_hash_table_iter_next(&oiter, &ok, &ov))
                orows.append({ QString::fromUtf8((const gchar *)ok), *(const guint *)ov });
            std::sort(orows.begin(), orows.end(),
                [](const OidRow &a, const OidRow &b){ return a.count > b.count; });

            html += "<table cellpadding='3'>";
            int shown = 0;
            for (const auto &r : orows) {
                if (shown >= 30) {
                    html += QString("<tr><td colspan='2' style='color:%1;'>"
                                    "&hellip; and %2 more OIDs</td></tr>")
                                .arg(dimColor).arg((int)orows.size() - shown);
                    break;
                }
                html += QString("<tr>"
                                "<td style='%1 color:%2;'>%3</td>"
                                "<td style='color:%4; padding-left:8px;'>&times;%5</td>"
                                "</tr>")
                            .arg(monoStyle, textColor,
                                 r.name.toHtmlEscaped(), dimColor).arg(r.count);
                shown++;
            }
            html += "</table><br>";
        }

        /* ── Section 6: Errors ──────────────────────────────────── */
        if (si->error_total > 0 && si->error_counts &&
            g_hash_table_size(si->error_counts) > 0) {
            html += QString("<h3 style='color:%1; margin-bottom:4px;'>SNMP Errors"
                            "<span style='font-weight:normal; font-size:10px;'>"
                            " (%2 total)</span></h3>")
                        .arg(headingColor).arg(si->error_total);
            html += "<table cellpadding='3'>";

            struct ErrRow { QString name; guint count; };
            QVector<ErrRow> erows;
            GHashTableIter eiter;
            gpointer ek, ev;
            g_hash_table_iter_init(&eiter, si->error_counts);
            while (g_hash_table_iter_next(&eiter, &ek, &ev))
                erows.append({ QString::fromUtf8((const gchar *)ek), *(const guint *)ev });
            std::sort(erows.begin(), erows.end(),
                [](const ErrRow &a, const ErrRow &b){ return a.count > b.count; });

            for (const auto &r : erows)
                html += QString("<tr>"
                                "<td style='%1 color:%2; padding-right:12px;'>%3</td>"
                                "<td style='color:%4;'><b>%5</b></td>"
                                "</tr>")
                            .arg(monoStyle, dimColor, r.name.toHtmlEscaped(),
                                 alertColor).arg(r.count);
            html += "</table><br>";
        }

        html += "</div>";
        addHtmlTextEdit(mainLayout, dlg, dark, html);
    }

    addCloseButton(mainLayout, dlg, dark);
    packet_analyzer_free_snmp_info(si);

    if (m_autoCloseTimer) m_autoCloseTimer->stop();
    m_contextMenuActive = true;
    hide();
    dlg->exec();
    deleteLater();
}

/* ── Syslog Information dialog ──────────────────────────────────────────── */
void ConnectionPopup::showSyslogInfoForRow(int row)
{
    if (row < 0 || row >= m_rowData.size() || !m_pair)
        return;

    const RowData &rd = m_rowData[row];

    capture_file *cf = (capture_file *)plugin_if_get_capture_file(
        extract_capture_file, NULL);

    QString src = QString::fromUtf8(m_pair->src_addr);
    QString dst = QString::fromUtf8(m_pair->dst_addr);

    QString portLabel;
    switch (rd.port) {
        case  514: portLabel = "Syslog (514)";      break;
        case  601: portLabel = "Syslog/TCP (601)";  break;
        case 6514: portLabel = "Syslog/TLS (6514)"; break;
        default:   portLabel = QString("port %1").arg(rd.port); break;
    }

    QString dlgTitle = QString("Syslog Information  \u2014  %1 \u2194 %2  (%3)")
                           .arg(src, dst, portLabel);

    if (!cf) {
        QMessageBox::warning(this, dlgTitle,
            "No capture file is currently loaded in Wireshark.");
        return;
    }

    bool looksLikeMAC = (src.count(':') == 5 && dst.count(':') == 5);

    syslog_info_t *sl = packet_analyzer_extract_syslog_info(
        cf, m_pair->src_addr, m_pair->dst_addr,
        (guint16)rd.port, looksLikeMAC ? TRUE : FALSE);

    bool dark = isDarkTheme();
    QVBoxLayout *mainLayout;
    QDialog *dlg = createInfoDialog(dlgTitle, dark, &mainLayout);

    if (!sl || !sl->found) {
        addSorryPlaceholder(mainLayout, dlg, dark, "Syslog", sl ? sl->matched_packets : 0);
    } else {
        QString html;
        QString headingColor = dark ? "#90caf9" : "#1565c0";
        QString textColor    = dark ? "#e0e0e0" : "#222";
        QString dimColor     = dark ? "#999"    : "#666";
        QString valColor     = dark ? "#c8e6c9" : "#1b5e20";
        QString warnColor    = dark ? "#ffcc80" : "#c05800";
        QString alertColor   = dark ? "#ef9a9a" : "#b71c1c";
        QString monoStyle    = "font-family:monospace;";

        /* Severity color helper */
        auto sevColor = [&](int sev) -> QString {
            if (sev <= 1) return alertColor;
            if (sev <= 3) return warnColor;
            if (sev == 4) return (dark ? "#ffe082" : "#f57f17");
            return dimColor;
        };

        html += QString("<div style='color:%1;'>").arg(textColor);

        /* ── Section 1: Session Summary ─────────────────────────── */
        html += QString("<h3 style='color:%1; margin-bottom:4px;'>Session Summary</h3>")
                    .arg(headingColor);
        html += "<table cellpadding='3'>";
        html += QString("<tr><td style='color:%1;'>Total syslog frames:</td>"
                        "<td><b>%2</b></td></tr>")
                    .arg(dimColor).arg(sl->matched_packets);
        if (sl->rfc3164_count && sl->rfc5424_count) {
            html += QString("<tr><td style='color:%1;'>Format:</td>"
                            "<td>RFC 3164: <b>%2</b>&nbsp;&nbsp;RFC 5424: <b>%3</b></td></tr>")
                        .arg(dimColor).arg(sl->rfc3164_count).arg(sl->rfc5424_count);
        } else if (sl->rfc5424_count) {
            html += QString("<tr><td style='color:%1;'>Format:</td>"
                            "<td>RFC 5424 (structured syslog)</td></tr>").arg(dimColor);
        } else {
            html += QString("<tr><td style='color:%1;'>Format:</td>"
                            "<td>RFC 3164 (BSD syslog)</td></tr>").arg(dimColor);
        }
        html += "</table><br>";

        /* ── Section 2: Severity Breakdown ──────────────────────── */
        static const char *sevNames[8] = {
            "Emergency (0)", "Alert (1)", "Critical (2)", "Error (3)",
            "Warning (4)",   "Notice (5)", "Informational (6)", "Debug (7)"
        };
        guint32 totalSev = 0;
        for (int i = 0; i < 8; i++) totalSev += sl->severity_counts[i];

        if (totalSev > 0) {
            html += QString("<h3 style='color:%1; margin-bottom:4px;'>Severity Distribution"
                            "<span style='font-weight:normal; font-size:10px;'>"
                            " (%2 messages)</span></h3>")
                        .arg(headingColor).arg(totalSev);
            html += "<table cellpadding='3'>";
            for (int i = 0; i < 8; i++) {
                if (!sl->severity_counts[i]) continue;
                guint32 pct = (sl->severity_counts[i] * 100) / totalSev;
                html += QString("<tr>"
                                "<td style='color:%1; min-width:160px;'>%2</td>"
                                "<td style='color:%3;'><b>%4</b></td>"
                                "<td style='color:%5; padding-left:6px; font-size:10px;'>"
                                "%6%</td>"
                                "</tr>")
                            .arg(sevColor(i))
                            .arg(QString::fromUtf8(sevNames[i]).toHtmlEscaped())
                            .arg(sevColor(i)).arg(sl->severity_counts[i])
                            .arg(dimColor).arg(pct);
            }
            html += "</table><br>";
        }

        /* ── Section 3: Facility Breakdown ──────────────────────── */
        if (sl->facility_counts && g_hash_table_size(sl->facility_counts) > 0) {
            html += QString("<h3 style='color:%1; margin-bottom:4px;'>Facility Breakdown</h3>")
                        .arg(headingColor);

            struct FacRow { QString name; guint count; };
            QVector<FacRow> frows;
            GHashTableIter fiter;
            gpointer fk, fv;
            g_hash_table_iter_init(&fiter, sl->facility_counts);
            while (g_hash_table_iter_next(&fiter, &fk, &fv))
                frows.append({ QString::fromUtf8((const gchar *)fk), *(const guint *)fv });
            std::sort(frows.begin(), frows.end(),
                [](const FacRow &a, const FacRow &b){ return a.count > b.count; });

            html += "<table cellpadding='3'>";
            for (const auto &r : frows)
                html += QString("<tr>"
                                "<td style='%1 color:%2; padding-right:12px;'>%3</td>"
                                "<td><b>%4</b></td>"
                                "</tr>")
                            .arg(monoStyle, dimColor,
                                 r.name.toHtmlEscaped()).arg(r.count);
            html += "</table><br>";
        }

        /* ── Section 4: Source Hostnames ────────────────────────── */
        if (sl->hostnames) {
            html += QString("<h3 style='color:%1; margin-bottom:4px;'>Source Hosts</h3>")
                        .arg(headingColor);
            html += "<table cellpadding='3'>";
            int shown = 0;
            for (GList *l = sl->hostnames; l; l = l->next) {
                if (shown >= 20) {
                    html += QString("<tr><td style='color:%1;'>&hellip; and more</td></tr>")
                                .arg(dimColor);
                    break;
                }
                html += QString("<tr><td style='%1 color:%2;'>%3</td></tr>")
                            .arg(monoStyle, valColor,
                                 QString::fromUtf8((const gchar *)l->data).toHtmlEscaped());
                shown++;
            }
            html += "</table><br>";
        }

        /* ── Section 5: Application / Process Names ─────────────── */
        if (sl->app_names) {
            html += QString("<h3 style='color:%1; margin-bottom:4px;'>Applications / Processes</h3>")
                        .arg(headingColor);
            html += "<table cellpadding='3'>";
            int shown = 0;
            for (GList *l = sl->app_names; l; l = l->next) {
                if (shown >= 30) {
                    html += QString("<tr><td style='color:%1;'>&hellip; and more</td></tr>")
                                .arg(dimColor);
                    break;
                }
                html += QString("<tr><td style='%1 color:%2;'>%3</td></tr>")
                            .arg(monoStyle, textColor,
                                 QString::fromUtf8((const gchar *)l->data).toHtmlEscaped());
                shown++;
            }
            html += "</table><br>";
        }

        /* ── Section 6: Critical Message Samples ────────────────── */
        if (sl->critical_msgs) {
            guint total = g_list_length(sl->critical_msgs);
            html += QString("<h3 style='color:%1; margin-bottom:4px;'>"
                            "Critical / Error Messages"
                            "<span style='font-weight:normal; font-size:10px;'>"
                            " (severity 0\u20133, up to 15 samples)</span></h3>")
                        .arg(headingColor);
            html += QString("<div style='font-size:10px; color:%1; margin-bottom:6px;'>"
                            "&#9888;&nbsp;These messages had Emergency / Alert / Critical"
                            " / Error severity and warrant investigation.</div>")
                        .arg(warnColor);
            int shown = 0;
            for (GList *l = sl->critical_msgs; l; l = l->next) {
                const gchar *msg = (const gchar *)l->data;
                if (!msg) continue;
                shown++;
                /* Colorize by embedded severity label */
                QString msgStr = QString::fromUtf8(msg);
                QString color  = msgStr.startsWith("[Emergency") || msgStr.startsWith("[Alert")
                               ? alertColor : warnColor;
                html += QString("<div style='%1 color:%2; padding:2px 0 2px 8px;'>"
                                "&#8226;&nbsp;%3</div>")
                            .arg(monoStyle, color, msgStr.toHtmlEscaped());
            }
            if ((guint)shown < total)
                html += QString("<div style='color:%1; padding-left:8px;'>"
                                "&hellip; and %2 more</div>")
                            .arg(dimColor).arg(total - shown);
            html += "<br>";
        }

        html += "</div>";
        addHtmlTextEdit(mainLayout, dlg, dark, html);
    }

    addCloseButton(mainLayout, dlg, dark);
    packet_analyzer_free_syslog_info(sl);

    if (m_autoCloseTimer) m_autoCloseTimer->stop();
    m_contextMenuActive = true;
    hide();
    dlg->exec();
    deleteLater();
}

/* ── SSH / SFTP / SCP Information dialog ───────────────────────────────── */
void ConnectionPopup::showSshInfoForRow(int row)
{
    if (row < 0 || row >= m_rowData.size() || !m_pair)
        return;

    const RowData &rd = m_rowData[row];

    capture_file *cf = (capture_file *)plugin_if_get_capture_file(
        extract_capture_file, NULL);

    QString src = QString::fromUtf8(m_pair->src_addr);
    QString dst = QString::fromUtf8(m_pair->dst_addr);

    QString dlgTitle = QString("SSH Information  \u2014  %1 \u2194 %2  (port %3)")
                           .arg(src, dst, QString::number(rd.port));

    if (!cf) {
        QMessageBox::warning(this, dlgTitle,
            "No capture file is currently loaded in Wireshark.");
        return;
    }

    bool looksLikeMAC = (src.count(':') == 5 && dst.count(':') == 5);

    ssh_info_t *si = packet_analyzer_extract_ssh_info(
        cf, m_pair->src_addr, m_pair->dst_addr,
        (guint16)rd.port, looksLikeMAC ? TRUE : FALSE);

    bool dark = isDarkTheme();
    QVBoxLayout *mainLayout;
    QDialog *dlg = createInfoDialog(dlgTitle, dark, &mainLayout);

    if (!si || !si->found) {
        addSorryPlaceholder(mainLayout, dlg, dark, "SSH", si ? si->matched_packets : 0);
    } else {
        QString headingColor = dark ? "#90caf9" : "#1565c0";
        QString textColor    = dark ? "#e0e0e0" : "#222";
        QString dimColor     = dark ? "#999"    : "#666";
        QString valColor     = dark ? "#e0e0e0" : "#1a1a1a";
        QString warnColor    = dark ? "#ffcc80" : "#c05800";
        QString alertColor   = dark ? "#ef9a9a" : "#b71c1c";
        QString okColor      = dark ? "#a5d6a7" : "#2e7d32";
        QString monoStyle    = "font-family:monospace; font-size:12px;";
        const QString tableStyle = "border-collapse:collapse; width:100%;";
        const QString cellStyle  = "padding:3px 6px 3px 0;";

        /* Is channel / auth data available (requires Wireshark decryption keys)? */
        bool hasDecryptedData =
            si->usernames        || si->auth_methods       ||
            si->auth_success_count > 0 || si->auth_failure_count > 0 ||
            si->has_shell        || si->has_exec            ||
            si->has_sftp         || si->has_scp             ||
            si->has_x11_forwarding || si->has_tcp_forwarding ||
            si->has_agent_forwarding;

        QString html = "<div style='font-family:sans-serif; font-size:13px;'>";

        /* Encryption notice when payload is opaque */
        if (!hasDecryptedData) {
            html += QString("<div style='background:%1; color:%2; padding:6px 10px; "
                            "border-radius:4px; margin-bottom:10px;'>"
                            "<b>\U0001f512 Encrypted Traffic</b> &mdash; SSH payload is "
                            "encrypted.  Only handshake data (version strings &amp; "
                            "algorithm negotiation) is visible.  Provide a decryption "
                            "key file in Wireshark preferences to reveal auth and channel "
                            "details.</div>")
                        .arg(dark ? "#332a00" : "#fffbe0", warnColor);
        }

        /* ── Section 1: Session Summary ─────────────────────────────── */
        html += QString("<h3 style='color:%1; margin-bottom:4px;'>Session Summary</h3>")
                    .arg(headingColor);
        html += QString("<table style='%1'>").arg(tableStyle);

        html += QString("<tr><td style='color:%1; %2'>SSH frames:</td>"
                        "<td style='%3'><b>%4</b></td></tr>")
                    .arg(dimColor, cellStyle, monoStyle).arg(si->matched_packets);

        guint bannerIdx = 0;
        for (GList *n = si->banners; n; n = n->next, bannerIdx++) {
            QString banner = QString::fromUtf8((gchar *)n->data);
            QString role   = (bannerIdx == 0) ? "Banner (1st seen)" : "Banner (2nd seen)";
            html += QString("<tr><td style='color:%1; %2'>%3:</td>"
                            "<td style='%4 color:%5;'>%6</td></tr>")
                        .arg(dimColor, cellStyle, role,
                             monoStyle, valColor, banner.toHtmlEscaped());
        }

        if (si->banners) {
            QString protoLabel = si->protocol_v2
                ? QString("<b style='color:%1;'>SSH-2 (secure)</b>").arg(okColor)
                : QString("<b style='color:%1;'>SSH-1 (legacy \u2014 insecure!)</b>").arg(alertColor);
            html += QString("<tr><td style='color:%1; %2'>Protocol:</td>"
                            "<td>%3</td></tr>")
                        .arg(dimColor, cellStyle, protoLabel);
        }

        if (si->kexinit_count > 2) {
            /* Both sides send KEXINIT so /2 gives re-key count */
            html += QString("<tr><td style='color:%1; %2'>Re-key events:</td>"
                            "<td style='%3'><b>%4</b></td></tr>")
                        .arg(dimColor, cellStyle, monoStyle)
                        .arg(si->kexinit_count / 2);
        }
        if (si->disconnect_count > 0)
            html += QString("<tr><td style='color:%1; %2'>Disconnects:</td>"
                            "<td style='color:%3;'>%4</td></tr>")
                        .arg(dimColor, cellStyle, alertColor).arg(si->disconnect_count);

        html += "</table><br>";

        /* ── Section 2: Key Exchange & Algorithms ──────────────────── */
        bool hasHandshake = si->kex_algorithms || si->host_key_algorithms ||
                            si->ciphers_c2s    || si->ciphers_s2c         ||
                            si->macs_c2s       || si->macs_s2c;
        if (hasHandshake) {
            html += QString("<h3 style='color:%1; margin-bottom:4px;'>"
                            "Key Exchange &amp; Algorithms</h3>").arg(headingColor);

            auto fmtAlgList = [&](GList *lst, int maxShow = 5) -> QString {
                if (!lst) return QString("<span style='color:%1;'>n/a</span>").arg(dimColor);
                QString s;
                int shown = 0;
                for (GList *n = lst; n && shown < maxShow; n = n->next, shown++) {
                    if (shown > 0) s += "<br>";
                    s += QString("<span style='%1 color:%2;'>%3</span>")
                             .arg(monoStyle, shown == 0 ? valColor : dimColor,
                                  QString::fromUtf8((gchar *)n->data).toHtmlEscaped());
                }
                int total = (int)g_list_length(lst);
                if (total > maxShow)
                    s += QString("<br><span style='color:%1;'>\u2026 +%2 more</span>")
                             .arg(dimColor).arg(total - maxShow);
                return s;
            };

            html += QString("<table style='%1'>").arg(tableStyle);
            if (si->kex_algorithms)
                html += QString("<tr><td style='color:%1; %2 vertical-align:top;'>KEX algorithms:</td>"
                                "<td>%3</td></tr>")
                            .arg(dimColor, cellStyle, fmtAlgList(si->kex_algorithms));
            if (si->host_key_algorithms)
                html += QString("<tr><td style='color:%1; %2 vertical-align:top;'>Host key types:</td>"
                                "<td>%3</td></tr>")
                            .arg(dimColor, cellStyle, fmtAlgList(si->host_key_algorithms));
            if (si->ciphers_c2s)
                html += QString("<tr><td style='color:%1; %2 vertical-align:top;'>Ciphers (C&#8594;S):</td>"
                                "<td>%3</td></tr>")
                            .arg(dimColor, cellStyle, fmtAlgList(si->ciphers_c2s));
            if (si->ciphers_s2c)
                html += QString("<tr><td style='color:%1; %2 vertical-align:top;'>Ciphers (S&#8594;C):</td>"
                                "<td>%3</td></tr>")
                            .arg(dimColor, cellStyle, fmtAlgList(si->ciphers_s2c));
            if (si->macs_c2s)
                html += QString("<tr><td style='color:%1; %2 vertical-align:top;'>MACs (C&#8594;S):</td>"
                                "<td>%3</td></tr>")
                            .arg(dimColor, cellStyle, fmtAlgList(si->macs_c2s));
            if (si->macs_s2c)
                html += QString("<tr><td style='color:%1; %2 vertical-align:top;'>MACs (S&#8594;C):</td>"
                                "<td>%3</td></tr>")
                            .arg(dimColor, cellStyle, fmtAlgList(si->macs_s2c));
            if (si->compress_c2s || si->compress_s2c) {
                QString compVal = si->compression_enabled
                    ? QString("<span style='color:%1;'>Enabled</span>").arg(okColor)
                    : QString("<span style='color:%1;'>None / disabled</span>").arg(dimColor);
                html += QString("<tr><td style='color:%1; %2'>Compression:</td>"
                                "<td>%3</td></tr>")
                            .arg(dimColor, cellStyle, compVal);
            }
            html += "</table><br>";
        }

        /* ── Section 3: Authentication ─────────────────────────────── */
        bool hasAuth = si->usernames || si->auth_methods ||
                       si->auth_success_count > 0 || si->auth_failure_count > 0;
        if (hasAuth) {
            html += QString("<h3 style='color:%1; margin-bottom:4px;'>Authentication</h3>")
                        .arg(headingColor);
            html += QString("<table style='%1'>").arg(tableStyle);

            for (GList *n = si->usernames; n; n = n->next) {
                html += QString("<tr><td style='color:%1; %2'>Username:</td>"
                                "<td style='%3 color:%4;'>%5</td></tr>")
                            .arg(dimColor, cellStyle, monoStyle, valColor,
                                 QString::fromUtf8((gchar *)n->data).toHtmlEscaped());
            }

            if (si->auth_methods) {
                QStringList methods;
                for (GList *n = si->auth_methods; n; n = n->next)
                    methods << QString::fromUtf8((gchar *)n->data);
                html += QString("<tr><td style='color:%1; %2'>Methods used:</td>"
                                "<td style='%3 color:%4;'>%5</td></tr>")
                            .arg(dimColor, cellStyle, monoStyle, valColor,
                                 methods.join(", ").toHtmlEscaped());
            }

            if (si->auth_success_count > 0)
                html += QString("<tr><td style='color:%1; %2'>Auth successes:</td>"
                                "<td style='color:%3;'><b>%4</b></td></tr>")
                            .arg(dimColor, cellStyle, okColor).arg(si->auth_success_count);
            if (si->auth_failure_count > 0)
                html += QString("<tr><td style='color:%1; %2'>Auth failures:</td>"
                                "<td style='color:%3;'><b>%4</b></td></tr>")
                            .arg(dimColor, cellStyle,
                                 si->auth_failure_count > 5 ? alertColor : warnColor)
                            .arg(si->auth_failure_count);

            html += "</table><br>";
        }

        /* ── Section 4: Channel Usage & Features ───────────────────── */
        if (hasDecryptedData || si->channel_count > 0) {
            html += QString("<h3 style='color:%1; margin-bottom:4px;'>"
                            "Channel Usage &amp; Features</h3>").arg(headingColor);
            html += QString("<table style='%1'>").arg(tableStyle);

            if (si->channel_count > 0)
                html += QString("<tr><td style='color:%1; %2'>Channels opened:</td>"
                                "<td style='%3'><b>%4</b></td></tr>")
                            .arg(dimColor, cellStyle, monoStyle).arg(si->channel_count);

            auto featureRow = [&](const QString &name, gboolean present,
                                  const QString &note = {}) {
                QString icon  = present ? "\u2705" : "\u274c";
                QString color = present ? okColor  : dimColor;
                QString noteHtml = note.isEmpty() ? ""
                    : QString(" <span style='color:%1; font-size:11px;'>%2</span>")
                          .arg(warnColor, note.toHtmlEscaped());
                html += QString("<tr><td style='color:%1; %2'>%3:</td>"
                                "<td style='color:%4;'>%5%6</td></tr>")
                            .arg(dimColor, cellStyle, name.toHtmlEscaped(),
                                 color, icon, noteHtml);
            };

            featureRow("Shell session",        si->has_shell);
            featureRow("Exec channel",         si->has_exec);
            featureRow("SFTP subsystem",        si->has_sftp);
            featureRow("SCP file transfer",     si->has_scp);
            featureRow("X11 forwarding",        si->has_x11_forwarding,
                       si->has_x11_forwarding ? "X Window System tunnel active" : "");
            featureRow("TCP port forwarding",   si->has_tcp_forwarding,
                       si->has_tcp_forwarding ? "tunnel-in-tunnel detected" : "");
            featureRow("SSH agent forwarding",  si->has_agent_forwarding,
                       si->has_agent_forwarding ? "credential forwarding active" : "");

            html += "</table><br>";
        }

        /* ── Section 5: Subsystems ─────────────────────────────────── */
        if (si->subsystems) {
            html += QString("<h3 style='color:%1; margin-bottom:4px;'>Subsystems</h3>")
                        .arg(headingColor);
            html += "<ul style='margin:0 0 8px 16px; padding:0;'>";
            for (GList *n = si->subsystems; n; n = n->next)
                html += QString("<li style='%1 color:%2;'>%3</li>")
                            .arg(monoStyle, valColor,
                                 QString::fromUtf8((gchar *)n->data).toHtmlEscaped());
            html += "</ul><br>";
        }

        /* ── Section 6: Exec Command Samples ──────────────────────── */
        if (si->exec_commands) {
            html += QString("<h3 style='color:%1; margin-bottom:4px;'>"
                            "Exec Commands (sampled)</h3>").arg(headingColor);
            for (GList *n = si->exec_commands; n; n = n->next) {
                QString cmd   = QString::fromUtf8((gchar *)n->data);
                bool    isScp = cmd.startsWith("scp ");
                html += QString("<div style='%1 color:%2; padding:2px 0 2px 8px;'>"
                                "&#8226;&nbsp;%3</div>")
                            .arg(monoStyle, isScp ? warnColor : valColor,
                                 cmd.toHtmlEscaped());
            }
            html += "<br>";
        }

        html += "</div>";
        addHtmlTextEdit(mainLayout, dlg, dark, html);
    }

    addCloseButton(mainLayout, dlg, dark);
    packet_analyzer_free_ssh_info(si);

    if (m_autoCloseTimer) m_autoCloseTimer->stop();
    m_contextMenuActive = true;
    hide();
    dlg->exec();
    deleteLater();
}


/* ── FTP Information dialog ─────────────────────────────────────────────── */
void ConnectionPopup::showFtpInfoForRow(int row)
{
    if (row < 0 || row >= m_rowData.size() || !m_pair) return;
    const RowData &rd = m_rowData[row];

    capture_file *cf = (capture_file *)plugin_if_get_capture_file(
        extract_capture_file, NULL);

    QString src = QString::fromUtf8(m_pair->src_addr);
    QString dst = QString::fromUtf8(m_pair->dst_addr);
    QString dlgTitle = QString("FTP Information  \u2014  %1 \u2194 %2  (port %3)")
                           .arg(src, dst, QString::number(rd.port));

    if (!cf) {
        QMessageBox::warning(this, dlgTitle,
            "No capture file is currently loaded in Wireshark.");
        return;
    }

    bool looksLikeMAC = (src.count(':') == 5 && dst.count(':') == 5);
    bool dark = isDarkTheme();

    ftp_info_t *fi = packet_analyzer_extract_ftp_info(
        cf, m_pair->src_addr, m_pair->dst_addr,
        (guint16)rd.port, looksLikeMAC ? TRUE : FALSE);

    QVBoxLayout *mainLayout;
    QDialog *dlg = createInfoDialog(dlgTitle, dark, &mainLayout);

    if (!fi || !fi->found) {
        addSorryPlaceholder(mainLayout, dlg, dark, "FTP", fi ? fi->matched_packets : 0);
    } else {
        QString headingColor = dark ? "#90caf9" : "#1565c0";
        QString valColor     = dark ? "#e0e0e0" : "#1a1a1a";
        QString alertColor   = dark ? "#ef9a9a" : "#b71c1c";
        QString warnColor    = dark ? "#ffcc80" : "#c05800";
        QString okColor      = dark ? "#a5d6a7" : "#2e7d32";

        QString html;

        /* ── 1. Session Summary ──────────────────────────────────── */
        html += QString("<h3 style='color:%1;margin:0 0 6px 0;'>Session Summary</h3>")
                    .arg(headingColor);
        html += "<table style='border-collapse:collapse;'>";
        html += QString("<tr><td style='padding:2px 12px 2px 0;'>Packets analysed</td>"
                        "<td><b style='color:%1;'>%2</b></td></tr>")
                    .arg(valColor).arg(fi->matched_packets);

        QString loginStatus;
        if (fi->login_success)
            loginStatus = QString("<b style='color:%1;'>Success (230)</b>").arg(okColor);
        else if (fi->login_failed)
            loginStatus = QString("<b style='color:%1;'>Failed (530)</b>").arg(alertColor);
        else
            loginStatus = "<i style='color:#888;'>Not observed</i>";
        html += "<tr><td style='padding:2px 12px 2px 0;'>Login result</td><td>"
                + loginStatus + "</td></tr>";

        if (fi->username && *fi->username)
            html += QString("<tr><td style='padding:2px 12px 2px 0;'>Username</td>"
                            "<td><b style='color:%1;'>%2</b></td></tr>")
                        .arg(alertColor)
                        .arg(QString::fromUtf8(fi->username).toHtmlEscaped());
        if (fi->password && *fi->password)
            html += QString("<tr><td style='padding:2px 12px 2px 0;'>Password</td>"
                            "<td><b style='color:%1;'>%2</b>&nbsp;"
                            "<span style='font-size:10px;color:%3;'>(cleartext!)</span></td></tr>")
                        .arg(alertColor)
                        .arg(QString::fromUtf8(fi->password).toHtmlEscaped())
                        .arg(alertColor);

        QString dataMode;
        if (fi->passive_mode && fi->active_mode) dataMode = "Active + Passive";
        else if (fi->passive_mode) dataMode = "Passive (PASV/EPSV)";
        else if (fi->active_mode)  dataMode = "Active (PORT/EPRT)";
        else                        dataMode = "&mdash;";
        html += QString("<tr><td style='padding:2px 12px 2px 0;'>Data mode</td>"
                        "<td><b>%1</b></td></tr>").arg(dataMode);

        html += QString("<tr><td style='padding:2px 12px 2px 0;'>Downloads (RETR)</td>"
                        "<td><b>%1</b></td></tr>").arg(fi->retr_count);
        html += QString("<tr><td style='padding:2px 12px 2px 0;'>Uploads (STOR/STOU)</td>"
                        "<td><b>%1</b></td></tr>").arg(fi->stor_count);
        html += QString("<tr><td style='padding:2px 12px 2px 0;'>Responses 2xx</td>"
                        "<td><b style='color:%1;'>%2</b></td></tr>")
                    .arg(okColor).arg(fi->success_count);
        html += QString("<tr><td style='padding:2px 12px 2px 0;'>Responses 4xx/5xx</td>"
                        "<td><b style='color:%1;'>%2</b></td></tr>")
                    .arg(fi->error_count ? alertColor : valColor).arg(fi->error_count);
        if (fi->server_banner && *fi->server_banner)
            html += QString("<tr><td style='padding:2px 12px 2px 0;'>Server banner</td>"
                            "<td><i>%1</i></td></tr>")
                        .arg(QString::fromUtf8(fi->server_banner).toHtmlEscaped());
        if (fi->system_type && *fi->system_type)
            html += QString("<tr><td style='padding:2px 12px 2px 0;'>System (SYST)</td>"
                            "<td>%1</td></tr>")
                        .arg(QString::fromUtf8(fi->system_type).toHtmlEscaped());
        html += "</table>";

        /* ── 2. FEAT ──────────────────────────────────────────────── */
        if (fi->features) {
            html += QString("<h3 style='color:%1;margin:12px 0 4px 0;'>Server Features (FEAT)</h3>")
                        .arg(headingColor);
            html += "<ul style='margin:0;padding-left:18px;'>";
            for (GList *n = fi->features; n; n = n->next)
                html += "<li>" + QString::fromUtf8((gchar *)n->data).toHtmlEscaped() + "</li>";
            html += "</ul>";
        }

        /* ── 3. Data Ports ───────────────────────────────────────── */
        if (fi->pasv_addrs || fi->port_addrs) {
            html += QString("<h3 style='color:%1;margin:12px 0 4px 0;'>Data Ports Negotiated</h3>")
                        .arg(headingColor);
            html += "<table style='border-collapse:collapse;'>";
            for (GList *n = fi->pasv_addrs; n; n = n->next)
                html += QString("<tr><td style='padding:2px 12px 2px 0;'>PASV/EPSV</td>"
                                "<td><b style='color:%1;'>%2</b></td></tr>")
                            .arg(valColor)
                            .arg(QString::fromUtf8((gchar *)n->data).toHtmlEscaped());
            for (GList *n = fi->port_addrs; n; n = n->next)
                html += QString("<tr><td style='padding:2px 12px 2px 0;'>PORT/EPRT</td>"
                                "<td><b style='color:%1;'>%2</b></td></tr>")
                            .arg(warnColor)
                            .arg(QString::fromUtf8((gchar *)n->data).toHtmlEscaped());
            html += "</table>";
        }

        /* ── 4. Command Usage ─────────────────────────────────────── */
        if (g_hash_table_size(fi->cmd_counts) > 0) {
            html += QString("<h3 style='color:%1;margin:12px 0 4px 0;'>Command Usage</h3>")
                        .arg(headingColor);
            html += "<table style='border-collapse:collapse;'>";
            GList *keys = g_hash_table_get_keys(fi->cmd_counts);
            auto cmpDesc = [](gconstpointer a, gconstpointer b, gpointer ht) -> gint {
                guint ca = GPOINTER_TO_UINT(g_hash_table_lookup((GHashTable*)ht, a));
                guint cb = GPOINTER_TO_UINT(g_hash_table_lookup((GHashTable*)ht, b));
                return (gint)cb - (gint)ca;
            };
            keys = g_list_sort_with_data(keys, cmpDesc, fi->cmd_counts);
            for (GList *n = keys; n; n = n->next) {
                const gchar *cmd = (gchar *)n->data;
                guint cnt = GPOINTER_TO_UINT(g_hash_table_lookup(fi->cmd_counts, cmd));
                QString c = QString::fromUtf8(cmd);
                QString color = (c=="PASS") ? alertColor :
                                (c=="RETR"||c=="STOR") ? okColor : valColor;
                html += QString("<tr><td style='padding:2px 16px 2px 0;'>"
                                "<b style='color:%1;font-family:monospace;'>%2</b></td>"
                                "<td>%3&times;</td></tr>")
                            .arg(color, c.toHtmlEscaped()).arg(cnt);
            }
            g_list_free(keys);
            html += "</table>";
        }

        /* ── 5. Files / Paths ─────────────────────────────────────── */
        if (fi->filenames) {
            html += QString("<h3 style='color:%1;margin:12px 0 4px 0;'>Files / Paths</h3>")
                        .arg(headingColor);
            html += "<ul style='margin:0;padding-left:18px;font-family:monospace;font-size:12px;'>";
            guint shown = 0;
            for (GList *n = fi->filenames; n && shown < 40; n = n->next, shown++)
                html += "<li>" + QString::fromUtf8((gchar *)n->data).toHtmlEscaped() + "</li>";
            guint total = g_list_length(fi->filenames);
            if (total > 40)
                html += QString("<li><i>&hellip; and %1 more</i></li>").arg(total - 40);
            html += "</ul>";
        }

        /* ── 6. Full Command Log ──────────────────────────────────── */
        if (fi->command_log) {
            html += QString("<h3 style='color:%1;margin:12px 0 4px 0;'>Command Log</h3>")
                        .arg(headingColor);
            html += "<div style='font-family:monospace;font-size:11px;line-height:1.5;'>";
            for (GList *n = fi->command_log; n; n = n->next) {
                QString entry = QString::fromUtf8((gchar *)n->data).toHtmlEscaped();
                QString color = entry.startsWith("USER") || entry.startsWith("PASS")
                                ? alertColor
                                : entry.startsWith("RETR") || entry.startsWith("STOR")
                                  ? okColor
                                  : (dark ? "#c0c0c0" : "#333");
                html += QString("<div style='color:%1;'>%2</div>").arg(color, entry);
            }
            html += "</div>";
        }

        addHtmlTextEdit(mainLayout, dlg, dark, html);
    }

    addCloseButton(mainLayout, dlg, dark);
    packet_analyzer_free_ftp_info(fi);

    if (m_autoCloseTimer) m_autoCloseTimer->stop();
    m_contextMenuActive = true;
    hide();
    dlg->exec();
    deleteLater();
}

/* ── Telnet Information dialog ──────────────────────────────────────────── */
void ConnectionPopup::showTelnetInfoForRow(int row)
{
    if (row < 0 || row >= m_rowData.size() || !m_pair) return;
    const RowData &rd = m_rowData[row];

    capture_file *cf = (capture_file *)plugin_if_get_capture_file(
        extract_capture_file, NULL);

    QString src = QString::fromUtf8(m_pair->src_addr);
    QString dst = QString::fromUtf8(m_pair->dst_addr);
    QString dlgTitle = QString("Telnet Information  \u2014  %1 \u2194 %2  (port %3)")
                           .arg(src, dst, QString::number(rd.port));

    if (!cf) {
        QMessageBox::warning(this, dlgTitle,
            "No capture file is currently loaded in Wireshark.");
        return;
    }

    bool looksLikeMAC = (src.count(':') == 5 && dst.count(':') == 5);
    bool dark = isDarkTheme();

    telnet_info_t *ti = packet_analyzer_extract_telnet_info(
        cf, m_pair->src_addr, m_pair->dst_addr,
        (guint16)rd.port, looksLikeMAC ? TRUE : FALSE);

    QVBoxLayout *mainLayout;
    QDialog *dlg = createInfoDialog(dlgTitle, dark, &mainLayout);
    /* Make it slightly taller to accommodate the session data section */
    dlg->resize(720, 640);

    if (!ti || !ti->found) {
        addSorryPlaceholder(mainLayout, dlg, dark, "Telnet", ti ? ti->matched_packets : 0);
    } else {
        QString headingColor = dark ? "#90caf9" : "#1565c0";
        QString valColor     = dark ? "#e0e0e0" : "#1a1a1a";
        QString alertColor   = dark ? "#ef9a9a" : "#b71c1c";
        QString warnColor    = dark ? "#ffcc80" : "#c05800";
        QString okColor      = dark ? "#a5d6a7" : "#2e7d32";

        QString html;

        /* Cleartext security notice */
        html += QString("<div style='background:%1;color:%2;padding:5px 10px;"
                        "border-radius:3px;margin-bottom:8px;font-size:11px;'>"
                        "<b>\u26a0 CLEARTEXT PROTOCOL:</b> All traffic including "
                        "credentials is transmitted unencrypted.</div>")
                    .arg(dark ? "#3a1a1a" : "#fff0f0",
                         dark ? "#ff9999" : "#aa0000");

        /* ── 1. Session Summary ──────────────────────────────────── */
        html += QString("<h3 style='color:%1;margin:0 0 6px 0;'>Session Summary</h3>")
                    .arg(headingColor);
        html += "<table style='border-collapse:collapse;'>";
        html += QString("<tr><td style='padding:2px 12px 2px 0;'>Packets analysed</td>"
                        "<td><b style='color:%1;'>%2</b></td></tr>")
                    .arg(valColor).arg(ti->matched_packets);
        html += QString("<tr><td style='padding:2px 12px 2px 0;'>Total data bytes</td>"
                        "<td><b>%1</b></td></tr>").arg(ti->total_data_bytes);
        if (ti->username && *ti->username)
            html += QString("<tr><td style='padding:2px 12px 2px 0;'>Username detected</td>"
                            "<td><b style='color:%1;'>%2</b></td></tr>")
                        .arg(alertColor)
                        .arg(QString::fromUtf8(ti->username).toHtmlEscaped());
        if (ti->password && *ti->password)
            html += QString("<tr><td style='padding:2px 12px 2px 0;'>Password detected</td>"
                            "<td><b style='color:%1;'>%2</b></td></tr>")
                        .arg(alertColor)
                        .arg(QString::fromUtf8(ti->password).toHtmlEscaped());
        html += "</table>";

        /* ── 2. Option Negotiations ──────────────────────────────── */
        html += QString("<h3 style='color:%1;margin:12px 0 4px 0;'>Option Negotiations</h3>")
                    .arg(headingColor);

        auto renderOpts = [&](GHashTable *ht, const QString &verb, const QString &color) {
            if (!ht || g_hash_table_size(ht) == 0) return;
            GList *keys = g_hash_table_get_keys(ht);
            for (GList *n = keys; n; n = n->next) {
                const gchar *opt = (gchar *)n->data;
                guint cnt = GPOINTER_TO_UINT(g_hash_table_lookup(ht, opt));
                html += QString("<div style='font-size:12px;padding:1px 0;'>"
                                "<span style='color:%1;font-weight:bold;font-family:monospace;'>"
                                "%2</span>&nbsp;%3")
                            .arg(color, verb, QString::fromUtf8(opt).toHtmlEscaped());
                if (cnt > 1)
                    html += QString("&nbsp;<span style='color:#888;font-size:10px;'>&times;%1</span>")
                                .arg(cnt);
                html += "</div>";
            }
            g_list_free(keys);
        };
        if (g_hash_table_size(ti->will_opts) + g_hash_table_size(ti->do_opts) +
            g_hash_table_size(ti->wont_opts) + g_hash_table_size(ti->dont_opts) == 0) {
            html += "<i style='color:#888;'>No IAC option negotiations captured.</i>";
        } else {
            renderOpts(ti->will_opts, "WILL", okColor);
            renderOpts(ti->do_opts,   "DO  ", okColor);
            renderOpts(ti->wont_opts, "WONT", warnColor);
            renderOpts(ti->dont_opts, "DONT", warnColor);
        }

        /* ── 3. Capabilities ─────────────────────────────────────── */
        html += QString("<h3 style='color:%1;margin:12px 0 4px 0;'>Capabilities Detected</h3>")
                    .arg(headingColor);
        html += "<table style='border-collapse:collapse;'>";
        auto capRow = [&](const QString &name, bool on, bool isRisk = false) {
            QString col = on ? (isRisk ? alertColor : okColor) : (dark ? "#555" : "#aaa");
            QString val = on ? (isRisk ? "Active (\u26a0 risk)" : "Active") : "Not negotiated";
            html += QString("<tr><td style='padding:2px 12px 2px 0;'>%1</td>"
                            "<td style='color:%2;'><b>%3</b></td></tr>")
                        .arg(name, col, val);
        };
        capRow("Echo",               ti->has_echo);
        capRow("Linemode",           ti->has_linemode);
        capRow("Window Size (NAWS)", ti->has_naws);
        capRow("Terminal Type",      ti->has_ttype);
        capRow("Authentication",     ti->has_auth);
        capRow("Encryption",         ti->has_encrypt);
        if (!ti->has_encrypt)
            html += QString("<tr><td colspan='2' style='font-size:11px;color:%1;padding-top:4px;'>"
                            "&#x26a0; No Telnet encryption option negotiated &mdash; "
                            "all traffic is cleartext</td></tr>")
                        .arg(alertColor);
        html += "</table>";

        /* ── 4. Session Data (up to 1 KB, scrollable) ────────────── */
        html += QString("<h3 style='color:%1;margin:12px 0 4px 0;'>Session Data "
                        "<span style='font-weight:normal;font-size:11px;color:#888;'>"
                        "(reassembled, up to 1&thinsp;KB)</span></h3>")
                    .arg(headingColor);
        if (ti->data_s2c && ti->data_s2c->len > 0) {
            QString data = QString::fromUtf8(ti->data_s2c->str, (int)ti->data_s2c->len)
                               .toHtmlEscaped();
            data.replace('\n', "<br>");
            html += QString("<div style='font-family:monospace;font-size:11px;"
                            "background:%1;color:%2;padding:8px;border-radius:3px;"
                            "white-space:pre-wrap;word-break:break-all;'>%3</div>")
                        .arg(dark ? "#1a1a2e" : "#f4f4f8",
                             dark ? "#d0e0ff" : "#1a1a4a",
                             data);
            if (ti->total_data_bytes > 1024)
                html += QString("<div style='font-size:10px;color:#888;margin-top:2px;'>"
                                "Showing 1&thinsp;KB of %1 bytes total.</div>")
                            .arg(ti->total_data_bytes);
        } else {
            html += "<p><i style='color:#888;'>No payload data captured "
                    "(Telnet option traffic only, or data not decoded by Wireshark).</i></p>";
        }

        addHtmlTextEdit(mainLayout, dlg, dark, html);
    }

    addCloseButton(mainLayout, dlg, dark);
    packet_analyzer_free_telnet_info(ti);

    if (m_autoCloseTimer) m_autoCloseTimer->stop();
    m_contextMenuActive = true;
    hide();
    dlg->exec();
    deleteLater();
}

/* ─────────────────────────────────────────────────────────────────────────
 * showNbnsInfoForRow  —  NBNS / NetBIOS Name Service (UDP 137)
 * ───────────────────────────────────────────────────────────────────────── */
void ConnectionPopup::showNbnsInfoForRow(int row)
{
    if (row < 0 || row >= m_rowData.size() || !m_pair) return;
    const RowData &rd = m_rowData[row];

    capture_file *cf = (capture_file *)plugin_if_get_capture_file(
        extract_capture_file, NULL);

    QString src = QString::fromUtf8(m_pair->src_addr);
    QString dst = QString::fromUtf8(m_pair->dst_addr);
    bool dark = isDarkTheme();

    if (!cf) {
        QMessageBox::warning(this, "NBNS Information",
            "No capture file is currently loaded in Wireshark.");
        return;
    }

    bool looksLikeMAC = (src.count(':') == 5 && dst.count(':') == 5);

    nbns_info_t *ni = packet_analyzer_extract_nbns_info(
        cf, m_pair->src_addr, m_pair->dst_addr, looksLikeMAC ? TRUE : FALSE);

    QString dlgTitle = QString("NBNS \u2014 %1 \u2194 %2  (port %3)")
                           .arg(src, dst, QString::number(rd.port));
    QVBoxLayout *mainLayout = nullptr;
    QDialog *dlg = createInfoDialog(dlgTitle, dark, &mainLayout);
    dlg->resize(600, 520);

    QString html;
    auto sec = [&](const QString &t) {
        html += QString("<h3 style='color:%1;border-bottom:1px solid %2;"
                        "padding-bottom:3px;margin-top:14px;'>%3</h3>")
                    .arg(dark ? "#82aaff" : "#1565c0",
                         dark ? "#444" : "#ccc", t);
    };
    auto kv = [&](const QString &k, const QString &v, const QString &col = {}) {
        html += QString("<tr><td style='color:%1;width:170px;vertical-align:top;"
                        "padding:1px 8px 1px 0;'>%2</td>"
                        "<td style='color:%3;vertical-align:top;padding:1px 0;'>"
                        "%4</td></tr>")
                    .arg(dark ? "#aaa" : "#555", k,
                         col.isEmpty() ? (dark ? "#e0e0e0" : "#222") : col, v);
    };

    /* ── 1. Summary ── */
    sec("Session Summary");
    html += "<table style='border-collapse:collapse;width:100%;'>";
    kv("Packets matched",  ni ? QString::number(ni->matched_packets) : "0");
    if (ni) {
        kv("Queries",        QString::number(ni->query_count));
        kv("Responses",      QString::number(ni->response_count));
        if (ni->registration_count)
            kv("Registrations", QString::number(ni->registration_count));
        if (ni->release_count)
            kv("Releases",      QString::number(ni->release_count));
        if (ni->refresh_count)
            kv("Refreshes",     QString::number(ni->refresh_count));
        if (ni->wack_count)
            kv("WACKs",         QString::number(ni->wack_count));
        if (ni->name_to_addr)
            kv("Unique names resolved", QString::number(g_hash_table_size(ni->name_to_addr)));
    }
    html += "</table>";

    /* ── 2. Name Resolution Table ── */
    if (ni && ni->entries) {
        sec("Name Resolution (responses)");
        html += "<table style='border-collapse:collapse;width:100%;'>";
        html += QString("<tr><th style='text-align:left;color:%1;padding:2px 8px 4px 0;"
                        "border-bottom:1px solid %2;'>NetBIOS Name</th>"
                        "<th style='text-align:left;color:%1;padding:2px 0 4px 0;"
                        "border-bottom:1px solid %2;'>IP Address</th>"
                        "<th style='text-align:left;color:%1;padding:2px 0 4px 0;"
                        "border-bottom:1px solid %2;'>Type</th></tr>")
                    .arg(dark ? "#aaa" : "#666", dark ? "#444" : "#ccc");
        for (GList *l = ni->entries; l; l = l->next) {
            nbns_entry_t *e = (nbns_entry_t *)l->data;
            html += QString("<tr><td style='font-family:monospace;color:%1;"
                            "padding:1px 8px 1px 0;'>%2</td>"
                            "<td style='font-family:monospace;color:%3;"
                            "padding:1px 8px 1px 0;'>%4</td>"
                            "<td style='color:%5;padding:1px 0;'>%6</td></tr>")
                        .arg(dark ? "#c3e88d" : "#1b5e20",
                             QString(e->name).toHtmlEscaped(),
                             dark ? "#82aaff" : "#0d47a1",
                             QString(e->addr).toHtmlEscaped(),
                             dark ? "#aaa" : "#555",
                             QString(e->opcode ? e->opcode : "").toHtmlEscaped());
        }
        html += "</table>";
    } else {
        sec("Name Resolution");
        html += "<p><i style='color:#888;'>No name-to-address responses captured.</i></p>";
    }

    /* ── 3. Protocol Note ── */
    html += QString("<p style='margin-top:16px;font-size:11px;color:%1;'>"
                    "<b>Note:</b> NBNS (NetBIOS Name Service) runs over UDP port&nbsp;137. "
                    "It provides name registration and resolution for legacy Windows "
                    "networking. Modern environments use DNS instead.</p>")
                .arg(dark ? "#888" : "#666");

    addHtmlTextEdit(mainLayout, dlg, dark, html);
    addCloseButton(mainLayout, dlg, dark);
    if (ni) packet_analyzer_free_nbns_info(ni);

    if (m_autoCloseTimer) m_autoCloseTimer->stop();
    m_contextMenuActive = true;
    hide();
    dlg->exec();
    deleteLater();
}

/* ─────────────────────────────────────────────────────────────────────────
 * showNbdgmInfoForRow  —  NetBIOS Datagram Service (UDP 138)
 * ───────────────────────────────────────────────────────────────────────── */
void ConnectionPopup::showNbdgmInfoForRow(int row)
{
    if (row < 0 || row >= m_rowData.size() || !m_pair) return;
    const RowData &rd = m_rowData[row];

    capture_file *cf = (capture_file *)plugin_if_get_capture_file(
        extract_capture_file, NULL);

    QString src = QString::fromUtf8(m_pair->src_addr);
    QString dst = QString::fromUtf8(m_pair->dst_addr);
    bool dark = isDarkTheme();

    if (!cf) {
        QMessageBox::warning(this, "NetBIOS Datagram Information",
            "No capture file is currently loaded in Wireshark.");
        return;
    }

    bool looksLikeMAC = (src.count(':') == 5 && dst.count(':') == 5);

    nbdgm_info_t *di = packet_analyzer_extract_nbdgm_info(
        cf, m_pair->src_addr, m_pair->dst_addr, looksLikeMAC ? TRUE : FALSE);

    QString dlgTitle = QString("NetBIOS Datagram \u2014 %1 \u2194 %2  (port %3)")
                           .arg(src, dst, QString::number(rd.port));
    QVBoxLayout *mainLayout = nullptr;
    QDialog *dlg = createInfoDialog(dlgTitle, dark, &mainLayout);
    dlg->resize(580, 480);

    QString html;
    auto sec = [&](const QString &t) {
        html += QString("<h3 style='color:%1;border-bottom:1px solid %2;"
                        "padding-bottom:3px;margin-top:14px;'>%3</h3>")
                    .arg(dark ? "#82aaff" : "#1565c0",
                         dark ? "#444" : "#ccc", t);
    };
    auto kv = [&](const QString &k, const QString &v) {
        html += QString("<tr><td style='color:%1;width:170px;vertical-align:top;"
                        "padding:1px 8px 1px 0;'>%2</td>"
                        "<td style='color:%3;vertical-align:top;padding:1px 0;'>"
                        "%4</td></tr>")
                    .arg(dark ? "#aaa" : "#555", k,
                         dark ? "#e0e0e0" : "#222", v);
    };

    /* ── 1. Summary ── */
    sec("Session Summary");
    html += "<table style='border-collapse:collapse;width:100%;'>";
    kv("Packets matched",  di ? QString::number(di->matched_packets) : "0");
    if (di) {
        if (di->direct_unique)  kv("Direct Unique datagrams",  QString::number(di->direct_unique));
        if (di->direct_group)   kv("Direct Group datagrams",   QString::number(di->direct_group));
        if (di->broadcast)      kv("Broadcast datagrams",      QString::number(di->broadcast));
        if (di->error_pkts)     kv("Datagram errors",          QString::number(di->error_pkts));
    }
    html += "</table>";

    /* ── 2. Datagram Types breakdown ── */
    if (di && di->dgm_types && g_hash_table_size(di->dgm_types) > 0) {
        sec("Datagram Types");
        html += "<table style='border-collapse:collapse;width:100%;'>";
        GHashTableIter it; gpointer k, v;
        g_hash_table_iter_init(&it, di->dgm_types);
        while (g_hash_table_iter_next(&it, &k, &v)) {
            kv(QString((const char *)k).toHtmlEscaped(),
               QString::number(GPOINTER_TO_UINT(v)));
        }
        html += "</table>";
    }

    /* ── 3. Source Names ── */
    if (di && di->src_names && g_hash_table_size(di->src_names) > 0) {
        sec("Source NetBIOS Names");
        html += "<table style='border-collapse:collapse;width:100%;'>";
        GHashTableIter it; gpointer k, v;
        g_hash_table_iter_init(&it, di->src_names);
        while (g_hash_table_iter_next(&it, &k, &v)) {
            html += QString("<tr><td style='font-family:monospace;color:%1;"
                            "padding:1px 8px 1px 0;'>%2</td>"
                            "<td style='color:%3;padding:1px 0;'>%4 pkt%5</td></tr>")
                        .arg(dark ? "#c3e88d" : "#1b5e20",
                             QString((const char *)k).toHtmlEscaped(),
                             dark ? "#aaa" : "#555",
                             QString::number(GPOINTER_TO_UINT(v)),
                             GPOINTER_TO_UINT(v) == 1 ? "" : "s");
        }
        html += "</table>";
    }

    /* ── 4. Destination Names ── */
    if (di && di->dst_names && g_hash_table_size(di->dst_names) > 0) {
        sec("Destination NetBIOS Names");
        html += "<table style='border-collapse:collapse;width:100%;'>";
        GHashTableIter it; gpointer k, v;
        g_hash_table_iter_init(&it, di->dst_names);
        while (g_hash_table_iter_next(&it, &k, &v)) {
            html += QString("<tr><td style='font-family:monospace;color:%1;"
                            "padding:1px 8px 1px 0;'>%2</td>"
                            "<td style='color:%3;padding:1px 0;'>%4 pkt%5</td></tr>")
                        .arg(dark ? "#ffcb6b" : "#e65100",
                             QString((const char *)k).toHtmlEscaped(),
                             dark ? "#aaa" : "#555",
                             QString::number(GPOINTER_TO_UINT(v)),
                             GPOINTER_TO_UINT(v) == 1 ? "" : "s");
        }
        html += "</table>";
    }

    /* ── 5. Protocol Note ── */
    html += QString("<p style='margin-top:16px;font-size:11px;color:%1;'>"
                    "<b>Note:</b> NetBIOS Datagram Service runs over UDP port&nbsp;138. "
                    "It carries Windows browser announcements, domain master browser "
                    "elections, and SMB browse-list traffic.</p>")
                .arg(dark ? "#888" : "#666");

    addHtmlTextEdit(mainLayout, dlg, dark, html);
    addCloseButton(mainLayout, dlg, dark);
    if (di) packet_analyzer_free_nbdgm_info(di);

    if (m_autoCloseTimer) m_autoCloseTimer->stop();
    m_contextMenuActive = true;
    hide();
    dlg->exec();
    deleteLater();
}

/* ─────────────────────────────────────────────────────────────────────────
 * showNbssInfoForRow  —  NetBIOS Session Service (TCP 139)
 * ───────────────────────────────────────────────────────────────────────── */
void ConnectionPopup::showNbssInfoForRow(int row)
{
    if (row < 0 || row >= m_rowData.size() || !m_pair) return;
    const RowData &rd = m_rowData[row];

    capture_file *cf = (capture_file *)plugin_if_get_capture_file(
        extract_capture_file, NULL);

    QString src = QString::fromUtf8(m_pair->src_addr);
    QString dst = QString::fromUtf8(m_pair->dst_addr);
    bool dark = isDarkTheme();

    if (!cf) {
        QMessageBox::warning(this, "NetBIOS Session Information",
            "No capture file is currently loaded in Wireshark.");
        return;
    }

    bool looksLikeMAC = (src.count(':') == 5 && dst.count(':') == 5);

    nbss_info_t *si = packet_analyzer_extract_nbss_info(
        cf, m_pair->src_addr, m_pair->dst_addr, looksLikeMAC ? TRUE : FALSE);

    QString dlgTitle = QString("NetBIOS Session \u2014 %1 \u2194 %2  (port %3)")
                           .arg(src, dst, QString::number(rd.port));
    QVBoxLayout *mainLayout = nullptr;
    QDialog *dlg = createInfoDialog(dlgTitle, dark, &mainLayout);
    dlg->resize(580, 480);

    QString html;
    auto sec = [&](const QString &t) {
        html += QString("<h3 style='color:%1;border-bottom:1px solid %2;"
                        "padding-bottom:3px;margin-top:14px;'>%3</h3>")
                    .arg(dark ? "#82aaff" : "#1565c0",
                         dark ? "#444" : "#ccc", t);
    };
    auto kv = [&](const QString &k, const QString &v, const QString &col = {}) {
        html += QString("<tr><td style='color:%1;width:180px;vertical-align:top;"
                        "padding:1px 8px 1px 0;'>%2</td>"
                        "<td style='color:%3;vertical-align:top;padding:1px 0;'>"
                        "%4</td></tr>")
                    .arg(dark ? "#aaa" : "#555", k,
                         col.isEmpty() ? (dark ? "#e0e0e0" : "#222") : col, v);
    };

    /* ── 1. Summary ── */
    sec("Session Summary");
    html += "<table style='border-collapse:collapse;width:100%;'>";
    kv("Packets matched",   si ? QString::number(si->matched_packets) : "0");
    if (si) {
        kv("Session requests",  QString::number(si->session_requests));
        kv("Session confirmed", QString::number(si->session_confirms),
           si->session_confirms > 0 ? (dark ? "#c3e88d" : "#2e7d32") : QString());
        kv("Session rejected",  QString::number(si->session_rejects),
           si->session_rejects > 0  ? (dark ? "#f07178" : "#c62828") : QString());
        if (si->keepalives)
            kv("Keepalives",    QString::number(si->keepalives));
        kv("Session messages",  QString::number(si->session_messages));
    }
    html += "</table>";

    /* ── 2. Session Pairs ── */
    if (si && si->sessions) {
        sec("Session Setup (Calling \u2192 Called)");
        html += "<table style='border-collapse:collapse;width:100%;'>";
        html += QString("<tr><th style='text-align:left;color:%1;padding:2px 8px 4px 0;"
                        "border-bottom:1px solid %2;'>Calling (client)</th>"
                        "<th style='text-align:left;color:%1;padding:2px 0 4px 0;"
                        "border-bottom:1px solid %2;'>Called (server)</th></tr>")
                    .arg(dark ? "#aaa" : "#666", dark ? "#444" : "#ccc");
        for (GList *l = si->sessions; l; l = l->next) {
            nbss_session_t *s = (nbss_session_t *)l->data;
            html += QString("<tr>"
                            "<td style='font-family:monospace;color:%1;"
                            "padding:2px 8px 2px 0;'>%2</td>"
                            "<td style='font-family:monospace;color:%3;"
                            "padding:2px 0;'>%4</td></tr>")
                        .arg(dark ? "#ffcb6b" : "#e65100",
                             QString(s->calling_name).toHtmlEscaped(),
                             dark ? "#82aaff" : "#1565c0",
                             QString(s->called_name).toHtmlEscaped());
        }
        html += "</table>";
    } else {
        sec("Session Setup");
        html += "<p><i style='color:#888;'>No NBT session request packets captured "
                "(only mid-session data, or port&nbsp;139 used for SMB pass-through).</i></p>";
    }

    /* ── 3. Protocol Note ── */
    html += QString("<p style='margin-top:16px;font-size:11px;color:%1;'>"
                    "<b>Note:</b> Port&nbsp;139 TCP is the NetBIOS Session Service (NBT). "
                    "It wraps SMB traffic for legacy Windows file and printer sharing. "
                    "Modern SMB uses port&nbsp;445 directly without NBT. "
                    "Right-click a port&nbsp;445 connection for SMB protocol details.</p>")
                .arg(dark ? "#888" : "#666");

    addHtmlTextEdit(mainLayout, dlg, dark, html);
    addCloseButton(mainLayout, dlg, dark);
    if (si) packet_analyzer_free_nbss_info(si);

    if (m_autoCloseTimer) m_autoCloseTimer->stop();
    m_contextMenuActive = true;
    hide();
    dlg->exec();
    deleteLater();
}

/* ── TCP Transport Details dialog ──────────────────────────────────────────
 * Shows aggregated TCP transport-layer stats for the selected pair/port:
 * flags observed, window size, MSS, negotiated options, RTT.              */
void ConnectionPopup::showTcpStatInfoForRow(int row)
{
    if (row < 0 || row >= m_rowData.size() || !m_pair) return;
    if (!m_enableTransportStats) {
        /* Tier 2: transport stats disabled — show informational dialog */
        bool dark = isDarkTheme();
        QVBoxLayout *lay = nullptr;
        QDialog *dlg = createInfoDialog("TCP Transport Details", dark, &lay);
        addHtmlTextEdit(lay, dlg, dark,
            "<p style='color:#888;font-style:italic;'>"
            "\u26a0&nbsp; TCP/UDP transport statistics are disabled.<br>"
            "Re-enable via <b>Settings \u2192 Performance</b>.</p>");
        addCloseButton(lay, dlg, dark);
        if (m_autoCloseTimer) m_autoCloseTimer->stop();
        m_contextMenuActive = true;
        hide();
        dlg->exec();
        deleteLater();
        return;
    }
    const RowData &rd = m_rowData[row];

    capture_file *cf = (capture_file *)plugin_if_get_capture_file(extract_capture_file, NULL);
    QString src = QString::fromUtf8(m_pair->src_addr);
    QString dst = QString::fromUtf8(m_pair->dst_addr);
    bool looksLikeMAC = (src.count(':') == 5 && dst.count(':') == 5);

    /* Tier 3: check cache before full scan */
    QString tcacheKey = AnalysisCache::tcpKey(m_pair->src_addr, m_pair->dst_addr, rd.port);
    tcp_stat_info_t *ti = s_analysisCache.tcpStat.value(tcacheKey, nullptr);
    bool tiFromCache = (ti != nullptr);
    if (!ti) {
        ti = packet_analyzer_extract_tcp_stat_info(
            cf, m_pair->src_addr, m_pair->dst_addr, rd.port,
            looksLikeMAC ? TRUE : FALSE);
        if (ti) s_analysisCache.tcpStat.insert(tcacheKey, ti);
    }

    bool dark = isDarkTheme();
    QString dlgTitle = QString("TCP Transport Details \u2014 %1 \u2194 %2  (port %3)")
                           .arg(src, dst, QString::number(rd.port));
    QVBoxLayout *mainLayout = nullptr;
    QDialog *dlg = createInfoDialog(dlgTitle, dark, &mainLayout);
    dlg->resize(520, 580);

    auto kv = [&](const QString &k, const QString &v) -> QString {
        return QString("<tr><td style='padding:3px 8px 3px 0;color:%1;white-space:nowrap;'>%2</td>"
                       "<td style='padding:3px 0;'>%3</td></tr>")
            .arg(dark ? "#aaa" : "#555", k.toHtmlEscaped(), v);
    };
    auto sec = [&](const QString &title) -> QString {
        return QString("<tr><td colspan='2' style='padding:10px 0 3px 0;"
                       "font-weight:bold;font-size:12px;color:%1;"
                       "border-bottom:1px solid %2;'>%3</td></tr>")
            .arg(dark ? "#00d9c0" : "#007a6e",
                 dark ? "#333" : "#ccc",
                 title.toHtmlEscaped());
    };

    QString html = QString("<table style='font-size:13px;width:100%;border-collapse:collapse;"
                           "color:%1;'>")
                       .arg(dark ? "#e8e8e8" : "#1a1a1a");

    if (!ti || !ti->found) {
        html += "<tr><td style='color:#888;font-style:italic;padding:8px 0;'>"
                "No TCP packets found for this pair/port in the current capture.</td></tr>";
    } else {
        /* ── 1. Flags observed ── */
        html += sec("Flags Observed");
        /* One row per flag: monospace abbrev | description | seen/not-seen */
        auto flag = [&](const char *abbrev, const char *desc, bool seen) -> QString {
            return QString(
                "<tr>"
                "<td style='padding:2px 8px 2px 0;white-space:nowrap;'>"
                "<b style='font-family:monospace;color:%1;'>%2</b>"
                "<span style='color:%3;font-size:11px;'>&nbsp;&nbsp;%4</span>"
                "</td>"
                "<td style='padding:2px 0;'>"
                "<span style='color:%5;font-weight:%6;'>%7</span>"
                "</td></tr>")
                .arg(dark ? "#e8e8e8" : "#1a1a1a")
                .arg(abbrev)
                .arg(dark ? "#777" : "#888")
                .arg(desc)
                .arg(seen ? (dark ? "#4caf50" : "#2e7d32") : (dark ? "#555" : "#bbb"))
                .arg(seen ? "bold" : "normal")
                .arg(seen ? "&#x2714;  Observed" : "&mdash;  Not seen");
        };
        html += flag("SYN", "Synchronize &mdash; connection initiation",    ti->saw_syn);
        html += flag("ACK", "Acknowledge &mdash; receipt confirmed",         ti->saw_ack);
        html += flag("FIN", "Finish &mdash; graceful connection close",      ti->saw_fin);
        html += flag("RST", "Reset &mdash; connection aborted",              ti->saw_rst);
        html += flag("PSH", "Push &mdash; deliver buffered data immediately",ti->saw_psh);
        html += flag("URG", "Urgent &mdash; out-of-band data present",       ti->saw_urg);
        html += flag("ECE", "ECN-Echo &mdash; congestion notification",      ti->saw_ece);
        html += flag("CWR", "Congestion Window Reduced",                     ti->saw_cwr);

        /* ── 2. Window & MSS ── */
        html += sec("Window Size & MSS");
        if (ti->win_count > 0) {
            double avg = ti->win_sum / ti->win_count;
            html += kv("Window min", QString("%1 bytes").arg(ti->win_min));
            html += kv("Window max", QString("%1 bytes").arg(ti->win_max));
            html += kv("Window avg", QString("%1 bytes").arg((quint64)avg));
            html += kv("Samples",    QString::number(ti->win_count));
        } else {
            html += kv("Window size", "<i style='color:#888;'>not captured</i>");
        }
        html += kv("MSS (advertised)",
                   ti->mss > 0 ? QString("%1 bytes").arg(ti->mss)
                                : "<i style='color:#888;'>not seen (no SYN captured)</i>");

        /* ── 3. Negotiated options ── */
        html += sec("Negotiated TCP Options");
        auto opt = [&](const char *name, bool seen) {
            html += kv(name, seen
                ? QString("<span style='color:%1;font-weight:bold;'>&#x2714; Present</span>")
                      .arg(dark ? "#4caf50" : "#2e7d32")
                : QString("<span style='color:%1;'>&#x2718; Not seen</span>")
                      .arg(dark ? "#666" : "#aaa"));
        };
        opt("SACK Permitted",   ti->sack_permitted);
        opt("Timestamps",       ti->timestamps);
        if (ti->window_scale >= 0)
            html += kv("Window Scale",
                       QString("shift = %1 (&times;%2)").arg(ti->window_scale).arg(1 << ti->window_scale));
        else
            html += kv("Window Scale", "<i style='color:#888;'>not advertised</i>");

        /* ── 4. RTT ── */
        html += sec("Round-Trip Time (from Wireshark analysis)");
        if (ti->rtt_count > 0) {
            double avg_rtt = ti->rtt_sum_ms / ti->rtt_count;
            html += kv("RTT min",  QString("%1 ms").arg(ti->rtt_min_ms, 0, 'f', 3));
            html += kv("RTT max",  QString("%1 ms").arg(ti->rtt_max_ms, 0, 'f', 3));
            html += kv("RTT avg",  QString("%1 ms").arg(avg_rtt, 0, 'f', 3));
            html += kv("Samples",  QString::number(ti->rtt_count));
        } else {
            html += "<tr><td colspan='2' style='color:#888;font-style:italic;padding:4px 0;'>"
                    "RTT data not available &mdash; normal if the capture started mid-session, "
                    "is one-directional, or contains only handshake/control packets "
                    "(no data segments and their ACKs in the same capture).</td></tr>";
        }

        /* ── 5. Health ── */
        html += sec("Stream Health");
        html += kv("Total packets matched", QString::number(ti->matched_packets));
        if (ti->retrans_count > 0)
            html += kv("Retransmissions",
                       QString("<span style='color:%1;font-weight:bold;'>%2</span>")
                           .arg(dark ? "#ff8a65" : "#c62828")
                           .arg(ti->retrans_count));
        else
            html += kv("Retransmissions",
                       QString("<span style='color:%1;'>0 (none detected)</span>")
                           .arg(dark ? "#4caf50" : "#2e7d32"));
        if (ti->ooo_count > 0)
            html += kv("Out-of-order",
                       QString("<span style='color:%1;font-weight:bold;'>%2</span>")
                           .arg(dark ? "#ff8a65" : "#c62828")
                           .arg(ti->ooo_count));
        else
            html += kv("Out-of-order",
                       QString("<span style='color:%1;'>0 (none detected)</span>")
                           .arg(dark ? "#4caf50" : "#2e7d32"));
    }

    html += "</table>";

    if (ti && ti->found) {
        html += QString("<p style='margin-top:14px;font-size:11px;color:%1;'>"
                        "<b>Note:</b> Window sizes are raw (unscaled). RTT requires both the "
                        "data segment and its ACK to be present in the capture. "
                        "Options are detected from SYN/SYN-ACK frames in the capture.</p>")
                    .arg(dark ? "#888" : "#666");
    }

    addHtmlTextEdit(mainLayout, dlg, dark, html);
    addCloseButton(mainLayout, dlg, dark);
    /* ti is owned by the cache — never free here */

    if (m_autoCloseTimer) m_autoCloseTimer->stop();
    m_contextMenuActive = true;
    hide();
    dlg->exec();
    deleteLater();
}

/* ── UDP Transport Details dialog ──────────────────────────────────────────
 * Shows aggregated UDP payload size stats and direction breakdown.         */
void ConnectionPopup::showUdpStatInfoForRow(int row)
{
    if (row < 0 || row >= m_rowData.size() || !m_pair) return;
    if (!m_enableTransportStats) {
        bool dark = isDarkTheme();
        QVBoxLayout *lay = nullptr;
        QDialog *dlg = createInfoDialog("UDP Transport Details", dark, &lay);
        addHtmlTextEdit(lay, dlg, dark,
            "<p style='color:#888;font-style:italic;'>"
            "\u26a0&nbsp; TCP/UDP transport statistics are disabled.<br>"
            "Re-enable via <b>Settings \u2192 Performance</b>.</p>");
        addCloseButton(lay, dlg, dark);
        if (m_autoCloseTimer) m_autoCloseTimer->stop();
        m_contextMenuActive = true;
        hide();
        dlg->exec();
        deleteLater();
        return;
    }
    const RowData &rd = m_rowData[row];

    capture_file *cf = (capture_file *)plugin_if_get_capture_file(extract_capture_file, NULL);
    QString src = QString::fromUtf8(m_pair->src_addr);
    QString dst = QString::fromUtf8(m_pair->dst_addr);
    bool looksLikeMAC = (src.count(':') == 5 && dst.count(':') == 5);

    /* Tier 3: check cache before full scan */
    QString ucacheKey = AnalysisCache::udpKey(m_pair->src_addr, m_pair->dst_addr, rd.port);
    udp_stat_info_t *ui = s_analysisCache.udpStat.value(ucacheKey, nullptr);
    bool uiFromCache = (ui != nullptr);
    if (!ui) {
        ui = packet_analyzer_extract_udp_stat_info(
            cf, m_pair->src_addr, m_pair->dst_addr, rd.port,
            looksLikeMAC ? TRUE : FALSE);
        if (ui) s_analysisCache.udpStat.insert(ucacheKey, ui);
    }

    bool dark = isDarkTheme();
    QString dlgTitle = QString("UDP Transport Details \u2014 %1 \u2194 %2  (port %3)")
                           .arg(src, dst, QString::number(rd.port));
    QVBoxLayout *mainLayout = nullptr;
    QDialog *dlg = createInfoDialog(dlgTitle, dark, &mainLayout);
    dlg->resize(480, 420);

    auto kv = [&](const QString &k, const QString &v) -> QString {
        return QString("<tr><td style='padding:3px 8px 3px 0;color:%1;white-space:nowrap;'>%2</td>"
                       "<td style='padding:3px 0;'>%3</td></tr>")
            .arg(dark ? "#aaa" : "#555", k.toHtmlEscaped(), v);
    };
    auto sec = [&](const QString &title) -> QString {
        return QString("<tr><td colspan='2' style='padding:10px 0 3px 0;"
                       "font-weight:bold;font-size:12px;color:%1;"
                       "border-bottom:1px solid %2;'>%3</td></tr>")
            .arg(dark ? "#00d9c0" : "#007a6e",
                 dark ? "#333" : "#ccc",
                 title.toHtmlEscaped());
    };

    QString html = QString("<table style='font-size:13px;width:100%;border-collapse:collapse;"
                           "color:%1;'>")
                       .arg(dark ? "#e8e8e8" : "#1a1a1a");

    if (!ui || !ui->found) {
        html += "<tr><td style='color:#888;font-style:italic;padding:8px 0;'>"
                "No UDP packets found for this pair/port in the current capture.</td></tr>";
    } else {
        /* ── 1. Payload size ── */
        html += sec("Payload Size (bytes per datagram)");
        if (ui->payload_count > 0) {
            double avg = ui->payload_sum / ui->payload_count;
            html += kv("Minimum",  QString("%1 bytes").arg(ui->payload_min));
            html += kv("Maximum",  QString("%1 bytes").arg(ui->payload_max));
            html += kv("Average",  QString("%1 bytes").arg((quint64)avg));
            html += kv("Datagrams", QString::number(ui->payload_count));
        } else {
            html += kv("Payload size", "<i style='color:#888;'>no udp.length field found</i>");
        }

        /* ── 2. Direction ── */
        html += sec("Traffic Direction");
        guint32 total = ui->pkts_a_to_b + ui->pkts_b_to_a;
        if (total > 0) {
            int pctAB = (int)((ui->pkts_a_to_b * 100) / total);
            int pctBA = 100 - pctAB;
            html += kv(QString("%1 &rarr; %2").arg(src.toHtmlEscaped(), dst.toHtmlEscaped()),
                       QString("%1 packets (%2%)")
                           .arg(ui->pkts_a_to_b).arg(pctAB));
            html += kv(QString("%1 &rarr; %2").arg(dst.toHtmlEscaped(), src.toHtmlEscaped()),
                       QString("%1 packets (%2%)")
                           .arg(ui->pkts_b_to_a).arg(pctBA));
            html += kv("Total packets", QString::number(total));

            /* Simple ASCII asymmetry bar */
            QString bar = "";
            int filled = pctAB / 5;
            bar += QString("<span style='color:%1;'>").arg(dark ? "#00d9c0" : "#007a6e");
            for (int i = 0; i < filled; i++) bar += "&#x2588;";
            bar += "</span>";
            for (int i = filled; i < 20; i++) bar += "&#x2591;";
            bar += QString(" &nbsp;%1% / %2%").arg(pctAB).arg(pctBA);
            html += QString("<tr><td colspan='2' style='padding:6px 0;font-family:monospace;'>"
                            "%1</td></tr>").arg(bar);
        }

        /* ── 3. Characteristics ── */
        html += sec("Datagram Characteristics");
        if (ui->payload_count > 0) {
            guint32 range = ui->payload_max - ui->payload_min;
            if (range == 0)
                html += kv("Size consistency",
                           "<span style='color:" + QString(dark ? "#4caf50" : "#2e7d32") + ";'>"
                           "Fixed-size datagrams (likely a structured protocol)</span>");
            else if (range < 64)
                html += kv("Size consistency", "Low variance &mdash; mostly uniform payload sizes");
            else if (ui->payload_max <= 508)
                html += kv("Size note", "All datagrams within safe unfragmented UDP size (&le;508 bytes)");
            else if (ui->payload_max > 1472)
                html += kv("Size note",
                           QString("<span style='color:%1;'>Large datagrams detected "
                                   "(max %2 bytes) &mdash; may fragment on standard MTU paths</span>")
                               .arg(dark ? "#ffb74d" : "#e65100")
                               .arg(ui->payload_max));
            else
                html += kv("Size consistency", "Variable payload sizes");
        }
        html += kv("Total matched packets", QString::number(ui->matched_packets));
    }

    html += "</table>";

    html += QString("<p style='margin-top:14px;font-size:11px;color:%1;'>"
                    "<b>Note:</b> Payload = UDP length field minus 8-byte header. "
                    "For application-layer details, right-click a row and select the "
                    "specific protocol (DNS, SNMP, NBNS, etc.) if applicable.</p>")
                .arg(dark ? "#888" : "#666");

    addHtmlTextEdit(mainLayout, dlg, dark, html);
    addCloseButton(mainLayout, dlg, dark);
    /* ui is owned by the cache — never free here */

    if (m_autoCloseTimer) m_autoCloseTimer->stop();
    m_contextMenuActive = true;
    hide();
    dlg->exec();
    deleteLater();
}
