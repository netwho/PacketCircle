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
#include <QVBoxLayout>
#include <QPushButton>
#include <QTextEdit>
#include <QPdfWriter>
#include <QFileDialog>
#include <QDateTime>
#include <QPixmap>
#include <QDebug>
#include <QTimer>
#include <QMenu>
#include <QMenuBar>
#include <QResizeEvent>
#include <QRegularExpression>
#include <QApplication>
#include <QScreen>
#include <algorithm>
#include <epan/plugin_if.h>

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
    , m_macBtn(nullptr)
    , m_ipBtn(nullptr)
    , m_selectAllBtn(nullptr)
    , m_selectSearchBtn(nullptr)
    , m_selectNoneBtn(nullptr)
    , m_applyFilterBtn(nullptr)
    , m_clearFilterBtn(nullptr)
    , m_reloadDataBtn(nullptr)
    , m_savePDFBtn(nullptr)
    , m_splitter(nullptr)
    , m_splitterSizesRestored(false)
    , m_viewStack(nullptr)
    , m_circleWidget(nullptr)
    , m_circleContainer(nullptr)
    , m_searchLineEdit(nullptr)
    , m_searchLabel(nullptr)
    , m_tableWidget(nullptr)
    , m_pairListWidget(nullptr)
    , m_pairListContainer(nullptr)
    , m_legendWidget(nullptr)
    , m_legendLayout(nullptr)
    , m_legendRow2Layout(nullptr)
    , m_lineThicknessCheckBox(nullptr)
    , m_pairListBlinkTimer(nullptr)
    , m_pairListBlinkState(false)
    , m_connectionPopup(nullptr)
    , m_analysisResult(NULL)
    , m_top_pairs(NULL)
    , m_circle_pairs(NULL)
    , m_topN(10)
    , m_useBytes(FALSE)
    , m_useMAC(FALSE)
    , m_darkTheme(isDarkTheme())
{
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
    if (m_viewStack && (viewIdx == 0 || viewIdx == 1)) {
        m_viewStack->setCurrentIndex(viewIdx);
        if (m_circleBtn) m_circleBtn->setChecked(viewIdx == 0);
        if (m_tableBtn) m_tableBtn->setChecked(viewIdx == 1);
    }

    bool lineThickness = settings.value("lineThickness", false).toBool();
    if (m_lineThicknessCheckBox) {
        m_lineThicknessCheckBox->setChecked(lineThickness);
    }

    settings.endGroup();
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

    /* Create view stack for circle/table */
    m_viewStack = new QStackedWidget(this);
    m_viewStack->addWidget(m_circleContainer);
    m_viewStack->addWidget(m_tableWidget);
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
    
    /* Make window resizable with a reasonable minimum size
     * 640x480 fits older laptops; 1280x780 is comfortable on 1080p */
    setMinimumSize(640, 480);
    resize(1280, 780);
    
    /* Set window title and flags */
    setWindowTitle("PacketCircle v.0.3.2");
    
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

    /* ---- Segment shape rules (shared by both themes) ---- */
    static const char *segmentShapeRules =
        /* Left segment */
        "#controlsToolbar QPushButton[seg_pos=\"left\"] {"
        "  border-top-left-radius: 4px;"
        "  border-bottom-left-radius: 4px;"
        "  border-top-right-radius: 0;"
        "  border-bottom-right-radius: 0;"
        "}"
        /* Middle segment */
        "#controlsToolbar QPushButton[seg_pos=\"mid\"] {"
        "  border-radius: 0;"
        "  border-left: none;"
        "}"
        /* Right segment */
        "#controlsToolbar QPushButton[seg_pos=\"right\"] {"
        "  border-top-left-radius: 0;"
        "  border-bottom-left-radius: 0;"
        "  border-top-right-radius: 4px;"
        "  border-bottom-right-radius: 4px;"
        "  border-left: none;"
        "}";

    /* ---- Dark theme toolbar ---- */
    static const char *darkToolbarStyle =
        "#controlsToolbar {"
        "  background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #3a3a3a, stop:1 #2b2b2b);"
        "  border: 1px solid #222;"
        "  border-radius: 4px;"
        "  padding: 4px;"
        "}"
        "#controlsToolbar QPushButton[segmented=\"true\"] {"
        "  background: #4a4a4a;"
        "  color: #d0d0d0;"
        "  border: 1px solid #555;"
        "  padding: 4px 10px;"
        "  font-size: 11px;"
        "  font-weight: bold;"
        "  min-height: 22px;"
        "}"
        "#controlsToolbar QPushButton[segmented=\"true\"]:checked {"
        "  background: #0078d4;"
        "  color: white;"
        "  border-color: #005a9e;"
        "}"
        "#controlsToolbar QPushButton[segmented=\"true\"]:hover {"
        "  background: #5a5a5a;"
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
        "#controlsToolbar QPushButton[segmented=\"true\"] {"
        "  background: #e0e0e0;"
        "  color: #333;"
        "  border: 1px solid #aaa;"
        "  padding: 4px 10px;"
        "  font-size: 11px;"
        "  font-weight: bold;"
        "  min-height: 22px;"
        "}"
        "#controlsToolbar QPushButton[segmented=\"true\"]:checked {"
        "  background: #0078d4;"
        "  color: white;"
        "  border-color: #005a9e;"
        "}"
        "#controlsToolbar QPushButton[segmented=\"true\"]:hover {"
        "  background: #d0d0d0;"
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
    m_tableBtn = makeSegBtn("Table", "right");
    m_circleBtn->setChecked(true);

    QButtonGroup *viewGroup = new QButtonGroup(this);
    viewGroup->setExclusive(true);
    viewGroup->addButton(m_circleBtn);
    viewGroup->addButton(m_tableBtn);

    connect(m_circleBtn, &QPushButton::clicked, this, [this]() { onCircleViewToggled(true); });
    connect(m_tableBtn, &QPushButton::clicked, this, [this]() { onTableViewToggled(true); });

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

    /* -- Weight checkbox -- */
    m_lineThicknessCheckBox = new QCheckBox("Weight", m_controlsWidget);
    m_lineThicknessCheckBox->setChecked(false);
    connect(m_lineThicknessCheckBox, &QCheckBox::toggled, this, &MainWindow::onLineThicknessToggled);

    /* -- Help button (created here so it exists before being added to layout) -- */
    QPushButton *helpBtn = new QPushButton("?", m_row1Widget);
    helpBtn->setToolTip("Show help and controls description");
    helpBtn->setFixedSize(26, 26);
    helpBtn->setStyleSheet(
        QString("QPushButton {"
        "  background: %1;"
        "  color: %2;"
        "  border: 1px solid %3;"
        "  border-radius: 13px;"
        "  font-weight: bold;"
        "  font-size: 15px;"
        "}"
        "QPushButton:hover {"
        "  background: %4;"
        "}")
        .arg(m_darkTheme ? "#4a4a4a" : "#d8d8d8")
        .arg(m_darkTheme ? "#e0e0e0" : "#333")
        .arg(m_darkTheme ? "#666" : "#aaa")
        .arg(m_darkTheme ? "#5a5a5a" : "#c0c0c0")
    );
    connect(helpBtn, &QPushButton::clicked, this, &MainWindow::onHelpClicked);

    /* Layout Row 1 */
    m_controlsRow1->addWidget(topLabel);
    m_controlsRow1->addWidget(m_top10Btn);
    m_controlsRow1->addWidget(m_top25Btn);
    m_controlsRow1->addWidget(m_top50Btn);
    m_controlsRow1->addSpacing(8);
    m_controlsRow1->addWidget(metricLabel);
    m_controlsRow1->addWidget(m_packetsBtn);
    m_controlsRow1->addWidget(m_bytesBtn);
    m_controlsRow1->addSpacing(8);
    m_controlsRow1->addWidget(viewLabel);
    m_controlsRow1->addWidget(m_circleBtn);
    m_controlsRow1->addWidget(m_tableBtn);
    m_controlsRow1->addSpacing(8);
    m_controlsRow1->addWidget(modeLabel);
    m_controlsRow1->addWidget(m_ipBtn);
    m_controlsRow1->addWidget(m_macBtn);
    m_controlsRow1->addSpacing(8);
    m_controlsRow1->addWidget(m_lineThicknessCheckBox);
    m_controlsRow1->addStretch();
    m_controlsRow1->addWidget(helpBtn);

    /* === Row 2: Actions + Search === */
    m_row2Widget = new QWidget(m_controlsWidget);
    m_controlsRow2 = new QHBoxLayout(m_row2Widget);
    m_controlsRow2->setSpacing(6);
    m_controlsRow2->setContentsMargins(0, 0, 0, 0);

    m_selectAllBtn = makeActionBtn("Select All");
    m_selectNoneBtn = makeActionBtn("Select None");
    m_applyFilterBtn = makeActionBtn("Filter");
    m_applyFilterBtn->setStyleSheet(
        m_applyFilterBtn->styleSheet() +
        "QPushButton { font-weight: bold; }"
    );
    m_clearFilterBtn = makeActionBtn("Clear");
    m_clearFilterBtn->setToolTip("Clear Wireshark display filter and show all connections");
    m_reloadDataBtn = makeActionBtn("Reload");
    m_savePDFBtn = makeActionBtn("PDF");
    m_savePDFBtn->setToolTip("Save report as PDF with circle visualization and IP pair list");
    m_selectSearchBtn = makeActionBtn("Select Results");
    m_selectSearchBtn->setToolTip("Select only the communication pairs matching the current search");
    m_selectSearchBtn->setEnabled(false);

    connect(m_selectAllBtn, &QPushButton::clicked, this, &MainWindow::onSelectAllClicked);
    connect(m_selectSearchBtn, &QPushButton::clicked, this, &MainWindow::onSelectSearchResultsClicked);
    connect(m_selectNoneBtn, &QPushButton::clicked, this, &MainWindow::onSelectNoneClicked);
    connect(m_applyFilterBtn, &QPushButton::clicked, this, &MainWindow::onApplyFilterClicked);
    connect(m_clearFilterBtn, &QPushButton::clicked, this, &MainWindow::onClearFilterClicked);
    connect(m_reloadDataBtn, &QPushButton::clicked, this, &MainWindow::onReloadDataClicked);
    connect(m_savePDFBtn, &QPushButton::clicked, this, &MainWindow::onSavePDFClicked);

    /* Search bar (moved from circle container) */
    m_searchLabel = new QLabel("Search IP", m_controlsWidget);
    m_searchLineEdit = new QLineEdit(m_controlsWidget);
    m_searchLineEdit->setPlaceholderText("Partial IP or CIDR (e.g., 192.168.1 or 10.0.0.0/24)");
    m_searchLineEdit->setMinimumWidth(160);

    connect(m_searchLineEdit, &QLineEdit::returnPressed, this, [this]() {
        applySearchFilter(m_searchLineEdit->text());
    });
    connect(m_searchLineEdit, &QLineEdit::textChanged, this, [this](const QString &text) {
        if (text.trimmed().isEmpty()) {
            applySearchFilter(QString());
        }
    });

    /* Layout Row 2 */
    m_controlsRow2->addWidget(m_selectAllBtn);
    m_controlsRow2->addWidget(m_selectSearchBtn);
    m_controlsRow2->addWidget(m_selectNoneBtn);
    m_controlsRow2->addWidget(m_applyFilterBtn);
    m_controlsRow2->addWidget(m_clearFilterBtn);
    m_controlsRow2->addSpacing(6);
    m_controlsRow2->addWidget(m_reloadDataBtn);
    m_controlsRow2->addWidget(m_savePDFBtn);
    m_controlsRow2->addSpacing(12);
    m_controlsRow2->addWidget(m_searchLabel);
    m_controlsRow2->addWidget(m_searchLineEdit, 1);

    m_controlsOuterLayout->addWidget(m_row1Widget);
    m_controlsOuterLayout->addWidget(m_row2Widget);

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
    
    /* Set compact fixed height for legend - taller for two rows */
    m_legendWidget->setMinimumHeight(70);
    m_legendWidget->setMaximumHeight(70);
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
    
    if (!m_analysisResult->pairs) {
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

    /* Clear CircleWidget's reference to old pairs first */
    if (m_circleWidget) {
        m_circleWidget->setPairs(NULL, NULL);
    }
    
    /* Free old circle_pairs list if it exists (only list nodes, pairs are owned by m_analysisResult) */
    if (m_circle_pairs) {
        g_list_free(m_circle_pairs);
        m_circle_pairs = NULL;
    }
    
    /* Don't free m_top_pairs - it contains pointers to pairs owned by m_analysisResult */
    /* The list nodes are small and will be cleaned up when m_analysisResult is freed */
    /* Setting to NULL prevents use-after-free issues */
    m_top_pairs = NULL;
    
    /* Get top pairs - we'll show both directions, so get enough pairs */
    m_top_pairs = packet_analyzer_get_top_pairs(m_analysisResult, m_topN, m_useBytes);
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
        
        /* Create a limited list with exactly top_n pairs for the circle widget */
        GList *iter;
        guint pair_count = 0;
        for (iter = m_top_pairs; iter && pair_count < m_topN; iter = iter->next, pair_count++) {
            m_circle_pairs = g_list_append(m_circle_pairs, iter->data);
        }
        
        m_circleWidget->setMaxPairs(m_topN);
        m_circleWidget->setUseBytes(m_useBytes);
        m_circleWidget->setPairs(m_circle_pairs, m_analysisResult->protocols);
        m_circleWidget->setSelectedPairs(m_selectedPairs);
        
        /* Note: m_circle_pairs list nodes will be freed in destructor or when updateViews is called again */
        /* The pairs themselves are owned by m_analysisResult, so we don't free them */
    }

    /* Update table view */
    m_tableWidget->setRowCount(0);
    m_tableCheckboxes.clear();
    GList *iter;
    guint row = 0;
    for (iter = m_top_pairs; iter; iter = iter->next, row++) {
        comm_pair_t *pair = (comm_pair_t *)iter->data;
        if (!pair || !pair->src_addr || !pair->dst_addr)
            continue;
            
        m_tableWidget->insertRow(row);

        /* Checkbox centered in cell */
        QCheckBox *checkbox = new QCheckBox();
        checkbox->setChecked(true);  /* All checked by default, synced with pair list later */
        QWidget *checkWidget = new QWidget();
        QHBoxLayout *checkLayout = new QHBoxLayout(checkWidget);
        checkLayout->addWidget(checkbox);
        checkLayout->setAlignment(Qt::AlignCenter);
        checkLayout->setContentsMargins(0, 0, 0, 0);
        m_tableWidget->setCellWidget(row, 0, checkWidget);
        
        /* Store checkbox-to-pair mapping for sync */
        m_tableCheckboxes[checkbox] = pair;
        
        /* Connect checkbox to sync with pair list */
        connect(checkbox, &QCheckBox::toggled, this, [this, pair](bool checked) {
            onTableCheckboxToggled(pair, checked);
        });

        /* Use resolved names for display if available, raw addresses otherwise */
        QString displaySrc = pair->resolved_src ? QString::fromUtf8(pair->resolved_src) : QString::fromUtf8(pair->src_addr);
        QString displayDst = pair->resolved_dst ? QString::fromUtf8(pair->resolved_dst) : QString::fromUtf8(pair->dst_addr);
        m_tableWidget->setItem(row, 1, new QTableWidgetItem(displaySrc));
        m_tableWidget->setItem(row, 2, new QTableWidgetItem(displayDst));
        
        /* Right-align numeric columns */
        QTableWidgetItem *pktItem = new QTableWidgetItem(QString::number(pair->packet_count));
        pktItem->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
        m_tableWidget->setItem(row, 3, pktItem);
        
        QTableWidgetItem *byteItem = new QTableWidgetItem(QString::number(pair->byte_count));
        byteItem->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
        m_tableWidget->setItem(row, 4, byteItem);
        
        m_tableWidget->setItem(row, 5, new QTableWidgetItem(pair->top_protocol ? pair->top_protocol : "Unknown"));
        
        /* Transport column: TCP / UDP / TCP+UDP */
        QString transport;
        if (pair->has_tcp && pair->has_udp) {
            transport = "TCP+UDP";
        } else if (pair->has_tcp) {
            transport = "TCP";
        } else if (pair->has_udp) {
            transport = "UDP";
        } else {
            transport = "-";
        }
        m_tableWidget->setItem(row, 6, new QTableWidgetItem(transport));
        
        /* Top Ports column: show top 3 destination ports with service names */
        QString portsStr;
        if (pair->dst_ports) {
            /* Collect ports and sort by packet count */
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
            /* Sort descending by count */
            std::sort(port_list.begin(), port_list.end(), 
                      [](const QPair<guint16, guint64> &a, const QPair<guint16, guint64> &b) {
                          return a.second > b.second;
                      });
            /* Show top 3 ports */
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
                if (name != QString::number(p.first)) {
                    port_strs << QString("%1/%2").arg(name).arg(p.first);
                } else {
                    port_strs << name;
                }
                shown++;
            }
            portsStr = port_strs.join(", ");
        }
        m_tableWidget->setItem(row, 7, new QTableWidgetItem(portsStr));
    }

    /* Update pair list */
    m_pairListWidget->clear();
    m_linkedPairs.clear();  /* Clear linked pairs map */
    
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
    
    for (auto group_it = pair_groups.begin(); group_it != pair_groups.end() && list_entry_count < m_topN; ++group_it) {
        QList<comm_pair_t*> &pairs = group_it.value();
        
        /* Sort pairs within group: A→B before B→A (alphabetically) */
        std::sort(pairs.begin(), pairs.end(), [](comm_pair_t *a, comm_pair_t *b) {
            QString a_src = QString::fromUtf8(a->src_addr);
            QString a_dst = QString::fromUtf8(a->dst_addr);
            QString b_src = QString::fromUtf8(b->src_addr);
            QString b_dst = QString::fromUtf8(b->dst_addr);
            
            if (a_src != b_src) {
                return a_src < b_src;
            }
            return a_dst < b_dst;
        });
        
        QListWidgetItem *first_item = nullptr;
        QListWidgetItem *second_item = nullptr;
        
        /* Create list items for each pair in the group */
        for (comm_pair_t *pair : pairs) {
            if (list_entry_count >= m_topN)
                break;
            
            /* Use resolved names for display, raw addresses for internal use */
            QString src_addr = pair->resolved_src ? QString::fromUtf8(pair->resolved_src) : QString::fromUtf8(pair->src_addr);
            QString dst_addr = pair->resolved_dst ? QString::fromUtf8(pair->resolved_dst) : QString::fromUtf8(pair->dst_addr);
            
            /* Truncate long addresses/names — will be refined by refreshPairListText() */
            src_addr = truncateIPv6Address(src_addr);
            dst_addr = truncateIPv6Address(dst_addr);
            
            /* Pad addresses for alignment */
            src_addr = src_addr.leftJustified(max_src_len, ' ');
            dst_addr = dst_addr.leftJustified(max_dst_len, ' ');
            
            /* Use arrow to show direction - use plain text with Unicode arrow (no HTML) */
            QString text = QString("%1 → %2").arg(src_addr).arg(dst_addr);
            QListWidgetItem *item = new QListWidgetItem(m_pairListWidget);
            item->setFlags(item->flags() | Qt::ItemIsUserCheckable);
            item->setCheckState(Qt::Checked);  /* All pairs visible by default */
            item->setData(Qt::UserRole, QVariant::fromValue((void*)pair));  /* Store pair pointer */
            item->setSizeHint(QSize(-1, 30));  /* Only constrain height, width adapts to list */
            item->setFont(fixedFont);
            item->setText(text);  /* Plain text - no HTML */
            
            m_pairListWidget->addItem(item);
            
            /* Track items for linking if bidirectional */
            if (!first_item) {
                first_item = item;
            } else if (!second_item) {
                second_item = item;
            }
            
            list_entry_count++;
        }
        
        /* Link checkboxes for bidirectional pairs */
        if (first_item && second_item && pairs.size() == 2) {
            m_linkedPairs[first_item] = second_item;
            m_linkedPairs[second_item] = first_item;
        }
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
        if (item->widget()) {
            delete item->widget();
        }
        delete item;
    }
    while ((item = m_legendRow2Layout->takeAt(0)) != NULL) {
        if (item->widget()) {
            delete item->widget();
        }
        delete item;
    }
    
    /* Clear checkbox hash */
    m_protocolCheckboxes.clear();

    /* Define protocol categories */
    struct ProtocolCategory {
        QString name;
        QStringList protocols;  /* Protocols that belong to this category */
        guint32 color;
    };
    
    ProtocolCategory categories[] = {
        {"ARP", QStringList() << "ARP" << "RARP", 0x87CEEB},  /* Sky Blue */
        {"ICMP", QStringList() << "ICMP" << "ICMPv6", 0xAFEEEE},  /* Pale Turquoise */
        {"TCP", QStringList() << "TCP", 0x90EE90},  /* Light Green */
        {"UDP", QStringList() << "UDP", 0xFFB347},  /* Pastel Orange */
        {"Infrastructure", QStringList() << "OSPF" << "BGP" << "RIP" << "RIPv2" << "EIGRP" 
                                         << "ISIS" << "IS-IS" << "IGMP" << "IGMPv2" << "IGMPv3"
                                         << "PIM" << "VRRP" << "HSRP" << "SCTP" << "DCCP", 0xFFE4B5},  /* Moccasin */
        {"Unknown", QStringList() << "Unknown" << "IP" << "IPv4" << "IPv6" << "Ethernet", 0x808080}  /* Gray */
    };
    
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
    
    /* Add category groups to legend - split into two rows */
    for (int i = 0; i < 6; i++) {
        ProtocolCategory &cat = categories[i];
        
        /* Check if any protocol in this category was found */
        bool category_found = false;
        for (const QString &proto : cat.protocols) {
            if (found_protocols.contains(proto)) {
                category_found = true;
                break;
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
        
        if (category_found) {
            /* Category found - normal checkbox */
            category_checkbox->setChecked(true);  /* Default to checked */
            category_checkbox->setEnabled(true);
        } else {
            /* Category not found - show dash (N/A) inside checkbox using tristate */
            category_checkbox->setTristate(true);
            category_checkbox->setCheckState(Qt::PartiallyChecked);  /* Shows dash/partial check */
            category_checkbox->setEnabled(false);   /* Disable if category not found */
        }
        
        if (m_darkTheme)
            category_checkbox->setStyleSheet("QCheckBox { font-size: 9pt; } QCheckBox:disabled { color: #888; }");
        else
            category_checkbox->setStyleSheet("QCheckBox { font-size: 9pt; } QCheckBox:disabled { color: #aaa; }");
        category_checkbox->setSizePolicy(QSizePolicy::Minimum, QSizePolicy::Fixed);
        
        /* Connect checkbox to filter function */
        if (category_found) {
            connect(category_checkbox, &QCheckBox::toggled, this, [this, cat](bool checked) {
                onProtocolCategoryToggled(cat.name, cat.protocols, checked);
            });
        }
        
        /* Store checkbox in hash using category name */
        m_protocolCheckboxes[cat.name] = category_checkbox;
        
        /* Add to appropriate row: first 3 in row 1, last 3 in row 2 */
        QHBoxLayout *targetLayout = (i < 3) ? m_legendLayout : m_legendRow2Layout;
        targetLayout->addWidget(color_label);
        targetLayout->addWidget(category_checkbox);
    }
    
    qDebug() << "updateLegend: Added 6 protocol categories to legend";
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
    
    if (m_analysisResult) {
        packet_analyzer_free_result(m_analysisResult);
    }
    m_analysisResult = result;
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
    }
}

/* Slot implementations */
void MainWindow::onTop10Clicked() { m_topN = 10; m_top25Btn->setChecked(false); m_top50Btn->setChecked(false); updateViews(); }
void MainWindow::onTop25Clicked() { m_topN = 25; m_top10Btn->setChecked(false); m_top50Btn->setChecked(false); updateViews(); }
void MainWindow::onTop50Clicked() { m_topN = 50; m_top10Btn->setChecked(false); m_top25Btn->setChecked(false); updateViews(); }
void MainWindow::onLineThicknessToggled(bool checked) 
{ 
    if (m_circleWidget) {
        m_circleWidget->setShowLineThickness(checked ? TRUE : FALSE);
    }
}

void MainWindow::onPacketsToggled(bool checked) { if (checked) { m_useBytes = FALSE; updateViews(); } }
void MainWindow::onBytesToggled(bool checked) { if (checked) { m_useBytes = TRUE; updateViews(); } }
void MainWindow::onCircleViewToggled(bool checked) { if (checked) m_viewStack->setCurrentIndex(0); }
void MainWindow::onTableViewToggled(bool checked) { if (checked) m_viewStack->setCurrentIndex(1); }
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

    /* Find the reverse pair (B→A) so the popup can merge port data from
     * both directions for a complete view.  Search through the same pair
     * list that the circle widget uses.                                     */
    comm_pair_t *reversePair = nullptr;
    if (m_circle_pairs) {
        for (GList *iter = m_circle_pairs; iter; iter = iter->next) {
            comm_pair_t *p = (comm_pair_t *)iter->data;
            if (!p || !p->src_addr || !p->dst_addr) continue;
            if (p == pair) continue;  /* skip self */
            if (g_strcmp0(p->src_addr, pair->dst_addr) == 0 &&
                g_strcmp0(p->dst_addr, pair->src_addr) == 0) {
                reversePair = p;
                break;
            }
        }
    }

    /* Create new connection popup with both directions */
    m_connectionPopup = new ConnectionPopup(pair, reversePair, m_useMAC, this);
    
    /* Position near the click point, offset slightly so cursor isn't on the popup */
    QPoint popupPos = globalPos + QPoint(10, 10);
    
    /* Ensure popup stays on screen */
    QScreen *screen = QApplication::screenAt(globalPos);
    if (screen) {
        QRect screenGeom = screen->availableGeometry();
        QSize popupSize = m_connectionPopup->sizeHint();
        if (popupPos.x() + popupSize.width() > screenGeom.right()) {
            popupPos.setX(globalPos.x() - popupSize.width() - 10);
        }
        if (popupPos.y() + popupSize.height() > screenGeom.bottom()) {
            popupPos.setY(globalPos.y() - popupSize.height() - 10);
        }
    }
    
    m_connectionPopup->move(popupPos);
    m_connectionPopup->show();
}

void MainWindow::onSelectAllClicked()
{
    /* Temporarily disconnect signal to avoid multiple update calls */
    disconnect(m_pairListWidget, &QListWidget::itemChanged, this, &MainWindow::onPairListItemChanged);
    
    /* Check all pairs in the list to make them visible */
    QSet<QListWidgetItem*> processed;  /* Track processed items to avoid double-processing linked pairs */
    
    for (int i = 0; i < m_pairListWidget->count(); i++) {
        QListWidgetItem *item = m_pairListWidget->item(i);
        if (!item || processed.contains(item))
            continue;
        
        item->setCheckState(Qt::Checked);
        processed.insert(item);
        
        /* If linked, also check the linked item */
        if (m_linkedPairs.contains(item)) {
            QListWidgetItem *linked = m_linkedPairs[item];
            linked->setCheckState(Qt::Checked);
            processed.insert(linked);
        }
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
    QSet<QListWidgetItem*> processed;

    for (int i = 0; i < m_pairListWidget->count(); i++) {
        QListWidgetItem *item = m_pairListWidget->item(i);
        if (!item || processed.contains(item))
            continue;

        bool isMatch = highlighted.contains(i);
        Qt::CheckState state = isMatch ? Qt::Checked : Qt::Unchecked;
        item->setCheckState(state);
        processed.insert(item);

        /* Also set linked pair to the same state */
        if (m_linkedPairs.contains(item)) {
            QListWidgetItem *linked = m_linkedPairs[item];
            linked->setCheckState(state);
            processed.insert(linked);
        }
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
    
    /* Uncheck all pairs in the list to hide them */
    QSet<QListWidgetItem*> processed;  /* Track processed items to avoid double-processing linked pairs */
    
    for (int i = 0; i < m_pairListWidget->count(); i++) {
        QListWidgetItem *item = m_pairListWidget->item(i);
        if (!item || processed.contains(item))
            continue;
        
        item->setCheckState(Qt::Unchecked);
        processed.insert(item);
        
        /* If linked, also uncheck the linked item */
        if (m_linkedPairs.contains(item)) {
            QListWidgetItem *linked = m_linkedPairs[item];
            linked->setCheckState(Qt::Unchecked);
            processed.insert(linked);
        }
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

void MainWindow::onHelpClicked()
{
    /* Use custom QDialog instead of QMessageBox for full size control */
    QDialog *helpDialog = new QDialog(this);
    helpDialog->setWindowTitle("Help - PacketCircle v.0.3.2");
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
        "• <b>Top 10/25/50</b>: Limit display to top N communication pairs<br/>"
        "• <b>Weight</b>: Enable/disable line weight variation based on traffic volume<br/>"
        "• <b>Packets/Bytes</b>: Sort pairs by packet count or byte count<br/>"
        "• <b>Circle/Table</b>: Switch between circular visualization and table view<br/>"
        "• <b>MAC/IP</b>: Display MAC address pairs or IP address pairs<br/>"
        "• <b>?</b> (top right): Open this help window"
        "</p>"

        "<h3>Action Buttons:</h3>"
        "<p style='margin-left: 0; padding-left: 0; font-weight: normal;'>"
        "• <b>Select All / Select None</b>: Show or hide all communication pairs<br/>"
        "• <b>Select Results</b>: Select only the communication pairs matching the current search (enabled after a search produces results)<br/>"
        "• <b>Filter</b>: Apply selected pairs as a Wireshark display filter (directional — filters by exact source→destination)<br/>"
        "• <b>Clear</b>: Select all pairs, clear the Wireshark display filter, and show all packets<br/>"
        "• <b>Reload</b>: Re-analyze current capture file (respects active Wireshark display filter)<br/>"
        "• <b>PDF</b>: Export a one-page PDF report containing the circle visualization and IP pair table"
        "</p>"

        "<h3>Search & Highlighting:</h3>"
        "<p style='font-weight: normal;'>The search bar supports several query types. "
        "Press <b>Enter</b> to search; matching nodes flash red in the circle and the pair list blinks in sync.</p>"
        "<p style='margin-left: 0; padding-left: 0; font-weight: normal;'>"
        "• <b>IP address</b> (partial): e.g. <code>192.168</code> or <code>10.0.0.1</code><br/>"
        "• <b>CIDR range</b>: e.g. <code>10.0.0.0/8</code> or <code>172.16.0.0/12</code><br/>"
        "• <b>MAC address</b> (partial, in MAC mode): e.g. <code>aa:bb</code> or <code>00:1a:2b</code><br/>"
        "• <b>TCP port</b>: e.g. <code>TCP 443</code> or <code>tcp 23</code> — highlights all pairs that use the specified TCP port<br/>"
        "• <b>UDP port</b>: e.g. <code>UDP 53</code> or <code>udp 5060</code> — highlights all pairs that use the specified UDP port"
        "</p>"
        "<p style='font-weight: normal;'>Port search works by inspecting the per-pair connection table (same data shown when clicking a line). "
        "It checks both directions of a communication pair. Clear the search box to remove all highlights.</p>"

        "<h3>Connection Details (Line Click):</h3>"
        "<p style='font-weight: normal;'>Click any communication line in the circle to open a "
        "<b>Connection Details</b> popup showing the port/socket breakdown for that pair. "
        "Data is aggregated from both directions (A→B and B→A).</p>"
        "<p style='margin-left: 0; padding-left: 0; font-weight: normal;'>"
        "• <b>Protocol</b>: Transport protocol for each port (TCP, UDP, or TCP+UDP), detected per-port<br/>"
        "• <b>Port</b>: Destination port number<br/>"
        "• <b>Service</b>: Well-known service name (HTTP, HTTPS, SSH, Telnet, DNS, SMB, etc.)<br/>"
        "• <b>Packets</b>: Number of packets observed on that port<br/>"
        "• <b>% of Total</b>: Share of total traffic for the pair"
        "</p>"
        "<p style='font-weight: normal;'><b>Right-click</b> a row in the popup to access:</p>"
        "<p style='margin-left: 0; padding-left: 0; font-weight: normal;'>"
        "• <b>Apply Filter in Wireshark</b>: Sets a bidirectional display filter matching both addresses "
        "and the selected port. Uses <code>ip.addr</code> / <code>eth.addr</code> for addresses "
        "and <code>tcp.port</code> or <code>udp.port</code> for the port.<br/>"
        "• <b>Follow TCP Stream</b>: Opens Wireshark's TCP stream reassembly dialog for that connection (TCP only).<br/>"
        "• <b>TCP Throughput Graph</b>: Opens Wireshark's TCP throughput time-series graph for the selected stream (TCP only).<br/>"
        "• <b>TCP Round-Trip Time Graph</b>: Opens Wireshark's TCP RTT graph for the selected stream (TCP only)."
        "</p>"
        "<p style='font-weight: normal;'>The popup auto-closes when the mouse leaves it. "
        "It remains open while a right-click context menu is active.</p>"

        "<h3>Filtering:</h3>"
        "<p style='font-weight: normal;'>The <b>Filter</b> button applies a Wireshark display filter for the currently checked pairs. "
        "Each pair is filtered by its exact direction — selecting only \"A → B\" filters to packets where A is the source "
        "and B is the destination. To see both directions, check both \"A → B\" and \"B → A\".</p>"
        "<p style='font-weight: normal;'>The <b>Clear</b> button resets everything: selects all pairs "
        "and sends an empty display filter to Wireshark so all packets are visible again.</p>"
        "<p style='font-weight: normal;'>Filters applied from the connection popup use <b>bidirectional</b> address matching "
        "so traffic in both directions is always included.</p>"

        "<h3>Protocol Legend:</h3>"
        "<p style='font-weight: normal;'>The protocol legend at the bottom shows protocol categories with checkboxes:</p>"
        "<p style='margin-left: 0; padding-left: 0; font-weight: normal;'>"
        "• <b>ARP</b>: Address Resolution Protocol (ARP, RARP)<br/>"
        "• <b>ICMP</b>: Internet Control Message Protocol (ICMP, ICMPv6)<br/>"
        "• <b>TCP</b>: Transmission Control Protocol<br/>"
        "• <b>UDP</b>: User Datagram Protocol<br/>"
        "• <b>Infra</b>: Routing and infrastructure protocols (OSPF, BGP, RIP, EIGRP, ISIS, IGMP, PIM, VRRP, HSRP, SCTP, DCCP)<br/>"
        "• <b>Unknown</b>: Unidentified or generic protocols (IP, IPv4, IPv6, Ethernet)"
        "</p>"
        "<p style='font-weight: normal;'>Uncheck a protocol category to hide its connections in the circle view. "
        "Protocols not found in the current capture show a dash (N/A). "
        "Mixed TCP+UDP pairs display as alternating dotted lines.</p>"

        "<h3>Node Pair List:</h3>"
        "<p style='font-weight: normal;'>Checkboxes control visibility of communication lines in the circle. "
        "Pairs with traffic in both directions (A→B and B→A) are grouped with linked checkboxes. "
        "Long hostnames and addresses are automatically truncated with \"...\" to fit the available panel width — "
        "drag the splitter between the circle and the list to resize.</p>"

        "<h3>Node Tooltips:</h3>"
        "<p style='font-weight: normal;'>Hover over a node in the circle to see detailed information:</p>"
        "<p style='margin-left: 0; padding-left: 0; font-weight: normal;'>"
        "• MAC and IP address<br/>"
        "• Bytes and packets sent/received<br/>"
        "• Services (target ports): A list of destination ports targeted on this node, "
        "sorted by packet count. Well-known ports are resolved to service names "
        "(e.g. HTTP/80, HTTPS/443, SMB/445, SSH/22, DNS/53, RDP/3389, etc.)."
        "</p>"

        "<h3>PDF Export:</h3>"
        "<p style='font-weight: normal;'>Click the <b>PDF</b> button to generate a one-page A4 landscape report containing:</p>"
        "<p style='margin-left: 0; padding-left: 0; font-weight: normal;'>"
        "• Header with the PacketCircle logo and report title<br/>"
        "• An introduction describing the analysis parameters<br/>"
        "• The circle visualization (rendered with a white background and darkened colors for print)<br/>"
        "• A table of all IP pairs with source, destination, packet count, and byte count"
        "</p>"

        "<h3>Preferences:</h3>"
        "<p style='font-weight: normal;'>PacketCircle automatically saves your preferences to "
        "<code>~/.PacketCircle/settings.ini</code>. The following settings are remembered between sessions:</p>"
        "<p style='margin-left: 0; padding-left: 0; font-weight: normal;'>"
        "• Window position and size<br/>"
        "• Splitter position (circle vs. pair list width)<br/>"
        "• Top N selection (10/25/50)<br/>"
        "• Packets vs. Bytes mode<br/>"
        "• MAC vs. IP mode<br/>"
        "• Circle vs. Table view<br/>"
        "• Line weight checkbox state"
        "</p>"
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
}

void MainWindow::onSavePDFClicked()
{
    /* Ask user where to save */
    QString defaultName = QString("PacketCircle_Report_%1.pdf")
                              .arg(QDateTime::currentDateTime().toString("yyyyMMdd_HHmmss"));
    QString filePath = QFileDialog::getSaveFileName(this, "Save PDF Report", defaultName, "PDF Files (*.pdf)");
    if (filePath.isEmpty())
        return;

    /* --- Setup PDF writer (A4 landscape) --- */
    QPdfWriter writer(filePath);
    writer.setPageSize(QPageSize(QPageSize::A4));
    writer.setPageOrientation(QPageLayout::Landscape);
    writer.setResolution(300);  /* 300 DPI for crisp output */
    writer.setPageMargins(QMarginsF(15, 15, 15, 15), QPageLayout::Millimeter);

    QPainter painter(&writer);
    if (!painter.isActive()) {
        QMessageBox::warning(this, "PDF Error", "Failed to create PDF file.");
        return;
    }

    int pageW = writer.width();
    int pageH = writer.height();
    int dpi = writer.resolution();

    /* Helper: mm to device units */
    auto mm = [dpi](double millimeters) -> int { return (int)(millimeters * dpi / 25.4); };

    /* ===== HEADER: Logo + Title ===== */
    int headerY = 0;

    /* Load logo from embedded resource */
    QPixmap logo(":/packetcircle/PacketCircle.png");
    int logoH = mm(18);
    if (!logo.isNull()) {
        QPixmap scaled = logo.scaledToHeight(logoH, Qt::SmoothTransformation);
        painter.drawPixmap(0, headerY, scaled);
        /* Title to the right of the logo */
        int textX = scaled.width() + mm(4);
        QFont titleFont("Helvetica", 28, QFont::Bold);
        painter.setFont(titleFont);
        painter.setPen(Qt::black);
        painter.drawText(textX, headerY, pageW - textX, logoH, Qt::AlignVCenter | Qt::AlignLeft, "PacketCircle Report");
    } else {
        /* No logo — just title */
        QFont titleFont("Helvetica", 28, QFont::Bold);
        painter.setFont(titleFont);
        painter.setPen(Qt::black);
        painter.drawText(0, headerY, pageW, logoH, Qt::AlignVCenter | Qt::AlignLeft, "PacketCircle Report");
    }

    headerY += logoH + mm(3);

    /* Thin separator line */
    painter.setPen(QPen(QColor(180, 180, 180), mm(0.3)));
    painter.drawLine(0, headerY, pageW, headerY);
    headerY += mm(4);

    /* ===== INTRO TEXT ===== */
    QFont introFont("Helvetica", 10);
    painter.setFont(introFont);
    painter.setPen(Qt::black);

    QString intro = QString(
        "This report was generated by the PacketCircle Wireshark plugin on %1. "
        "It visualizes the top %2 communication pairs from the analysed capture, "
        "sorted by %3. The circle diagram on the left shows network endpoints as nodes "
        "with connections colored by protocol. The table on the right lists each "
        "directional IP pair with packet and byte counts."
    ).arg(QDateTime::currentDateTime().toString("yyyy-MM-dd HH:mm:ss"))
     .arg(m_topN)
     .arg(m_useBytes ? "byte volume" : "packet count");

    QRect introRect(0, headerY, pageW, mm(30));
    QRect introBound;
    painter.drawText(introRect, Qt::AlignLeft | Qt::TextWordWrap, intro, &introBound);
    headerY = introBound.bottom() + mm(5);

    /* ===== MAIN CONTENT: Circle (left) + IP Pair List (right) ===== */
    int footerH = mm(8);  /* Reserve space for footer */
    int contentH = pageH - headerY - footerH;
    int circleW = (int)(pageW * 0.62);
    int listX = circleW + mm(3);
    int listW = pageW - listX;

    /* --- Render Circle visualization with PDF-optimized colors --- */
    if (m_circleWidget) {
        /* Render at high resolution with white background and dark colors */
        int renderSize = 2000;  /* Large render for crisp output */
        QPixmap circlePixmap = m_circleWidget->renderForPDF(renderSize, renderSize);
        if (!circlePixmap.isNull()) {
            /* Scale to fit the left area while keeping aspect ratio */
            QPixmap scaled = circlePixmap.scaled(circleW, contentH, Qt::KeepAspectRatio, Qt::SmoothTransformation);
            /* Center vertically in the left area */
            int cy = headerY + (contentH - scaled.height()) / 2;
            painter.drawPixmap(0, cy, scaled);
        }
    }

    /* --- Render IP Pair List as a table --- */
    QFont tableHeaderFont("Helvetica", 9, QFont::Bold);
    QFont tableFont("Courier", 8);
    QFontMetrics thfm(tableHeaderFont, &writer);
    QFontMetrics tfm(tableFont, &writer);
    int rowH = tfm.height() + mm(1.5);
    int tableY = headerY;

    /* Column widths — account for left padding mm(1) so columns fit within listW */
    int tablePad = mm(1);
    int usableW = listW - tablePad - mm(1);  /* left pad + right pad */
    int colSrc = (int)(usableW * 0.28);
    int colDst = (int)(usableW * 0.28);
    int colPkts = (int)(usableW * 0.20);
    int colBytes = usableW - colSrc - colDst - colPkts;

    /* Draw table header background */
    painter.setPen(Qt::NoPen);
    painter.setBrush(QColor(60, 60, 60));
    int headerRowH = thfm.height() + mm(2);
    painter.drawRect(listX, tableY, listW, headerRowH);

    /* Draw table header text */
    painter.setPen(Qt::white);
    painter.setFont(tableHeaderFont);
    int tx = listX + mm(1);
    int textVCenter = tableY + (headerRowH - thfm.height()) / 2;
    painter.drawText(tx, textVCenter, colSrc, headerRowH, Qt::AlignVCenter, "Source");
    tx += colSrc;
    painter.drawText(tx, textVCenter, colDst, headerRowH, Qt::AlignVCenter, "Destination");
    tx += colDst;
    painter.drawText(tx, textVCenter, colPkts, headerRowH, Qt::AlignVCenter | Qt::AlignRight, "Packets");
    tx += colPkts;
    painter.drawText(tx, textVCenter, colBytes, headerRowH, Qt::AlignVCenter | Qt::AlignRight, "Bytes");

    tableY += headerRowH;

    /* Draw data rows from pair list */
    painter.setFont(tableFont);
    int rowCount = 0;
    int tableBottom = headerY + contentH;  /* Don't grow past the footer area */
    int maxRows = (tableBottom - tableY) / rowH;

    for (int i = 0; i < m_pairListWidget->count() && rowCount < maxRows; i++) {
        QListWidgetItem *item = m_pairListWidget->item(i);
        if (!item)
            continue;

        comm_pair_t *pair = (comm_pair_t *)item->data(Qt::UserRole).value<void*>();
        if (!pair)
            continue;

        /* Alternating row background */
        if (rowCount % 2 == 0) {
            painter.setPen(Qt::NoPen);
            painter.setBrush(QColor(240, 240, 240));
            painter.drawRect(listX, tableY, listW, rowH);
        }

        painter.setPen(Qt::black);
        tx = listX + mm(1);
        /* Use resolved names in the PDF table for display */
        QString src = pair->resolved_src ? QString::fromUtf8(pair->resolved_src) : QString::fromUtf8(pair->src_addr);
        QString dst = pair->resolved_dst ? QString::fromUtf8(pair->resolved_dst) : QString::fromUtf8(pair->dst_addr);
        painter.drawText(tx, tableY, colSrc, rowH, Qt::AlignVCenter, src);
        tx += colSrc;
        painter.drawText(tx, tableY, colDst, rowH, Qt::AlignVCenter, dst);
        tx += colDst;
        painter.drawText(tx, tableY, colPkts - mm(1), rowH, Qt::AlignVCenter | Qt::AlignRight,
                         QString::number(pair->packet_count));
        tx += colPkts;
        painter.drawText(tx, tableY, colBytes - mm(1), rowH, Qt::AlignVCenter | Qt::AlignRight,
                         QString::number(pair->byte_count));

        tableY += rowH;
        rowCount++;
    }

    /* Table border */
    painter.setPen(QPen(QColor(180, 180, 180), mm(0.2)));
    painter.setBrush(Qt::NoBrush);
    painter.drawRect(listX, headerY, listW, tableY - headerY);

    /* ===== FOOTER ===== */
    QFont footerFont("Helvetica", 7);
    painter.setFont(footerFont);
    painter.setPen(QColor(140, 140, 140));
    QFontMetrics ffm(footerFont, &writer);
    int footerTextH = ffm.height();
    painter.drawText(0, pageH - footerTextH - mm(1), pageW, footerTextH, Qt::AlignCenter,
                     QString("Generated by PacketCircle v.0.3.2 — %1")
                         .arg(QDateTime::currentDateTime().toString("yyyy-MM-dd HH:mm:ss")));

    painter.end();

    QMessageBox::information(this, "PDF Saved", QString("Report saved to:\n%1").arg(filePath));
}

void MainWindow::onReloadDataClicked()
{
    qDebug() << "MainWindow::onReloadDataClicked: Reloading data";
    /* Call the bridge function to reload data from current capture file */
    circle_vis_reload_data();
}

void MainWindow::updateSearchBarForMode()
{
    if (!m_searchLabel || !m_searchLineEdit) return;

    if (m_useMAC) {
        m_searchLabel->setText("Search MAC");
        m_searchLineEdit->setPlaceholderText("Partial MAC (e.g., aa:bb or 00:1a:2b)");
    } else {
        m_searchLabel->setText("Search");
        m_searchLineEdit->setPlaceholderText("IP, CIDR, or port (e.g., 10.0.0.0/24, TCP 443, UDP 53)");
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

    /* Reserve space for checkbox (~30px) + arrow " → " + safety margin */
    int reservedPx = fm.horizontalAdvance(" \xE2\x86\x92 ") + 50;
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

        /* Apply IPv6/MAC truncation first */
        src = truncateIPv6Address(src);
        dst = truncateIPv6Address(dst);

        /* Then truncate long names (hostnames, etc.) to fit the available width */
        src = truncateDisplayName(src, maxCharsPerAddr);
        dst = truncateDisplayName(dst, maxCharsPerAddr);

        entries[i].src = src;
        entries[i].dst = dst;
        if ((guint)src.length() > max_src_len) max_src_len = (guint)src.length();
        if ((guint)dst.length() > max_dst_len) max_dst_len = (guint)dst.length();
    }

    /* Update each item's text with aligned columns */
    for (int i = 0; i < m_pairListWidget->count(); i++) {
        QListWidgetItem *item = m_pairListWidget->item(i);
        if (entries[i].src.isEmpty() && entries[i].dst.isEmpty()) continue;
        QString src = entries[i].src.leftJustified(max_src_len, ' ');
        QString dst = entries[i].dst.leftJustified(max_dst_len, ' ');
        item->setText(QString("%1 \xE2\x86\x92 %2").arg(src).arg(dst));
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
            /* MAC address - abbreviate to first:...:last */
            return QString("%1:..:%2").arg(mac_parts.first()).arg(mac_parts.last());
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
    
    /* Get first group (first 4 hex digits) */
    QString first = parts.first();
    /* Get last group (last 4 hex digits) */
    QString last = parts.last();
    
    /* Handle compressed IPv6 (::) - if last part is empty, look for last non-empty */
    if (last.isEmpty() && parts.size() > 1) {
        for (qsizetype i = parts.size() - 1; i >= 0; i--) {
            if (!parts[i].isEmpty()) {
                last = parts[i];
                break;
            }
        }
    }
    
    /* Limit to 4 hex digits each */
    if (first.length() > 4) {
        first = first.left(4);
    }
    if (last.length() > 4) {
        last = last.right(4);
    }
    
    /* Return truncated format: first4:...:last4 */
    return QString("%1:...:%2").arg(first).arg(last);
}

QString MainWindow::createFilterString()
{
    QList<comm_pair_t*> active_pairs = getActivePairsForFilter();
    if (active_pairs.isEmpty())
        return QString();

    QStringList filters;
    for (comm_pair_t *pair : active_pairs) {
        if (m_useMAC) {
            filters << QString("(eth.src == %1 && eth.dst == %2)")
                       .arg(pair->src_addr).arg(pair->dst_addr);
        } else {
            filters << QString("(ip.src == %1 && ip.dst == %2)")
                       .arg(pair->src_addr).arg(pair->dst_addr);
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
        if (m_circleWidget) {
            m_circleWidget->setHighlightedLabels(highlighted_labels);
        }
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

    /* --- Detect port search: "TCP <port>" or "UDP <port>" --- */
    bool is_port_search = false;
    bool port_search_tcp = false;
    bool port_search_udp = false;
    guint16 port_search_num = 0;

    {
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
    }

    bool is_cidr = !is_port_search && trimmed.contains('/') && parse_cidr(trimmed, nullptr, nullptr);

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

            if (is_port_search) {
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
            } else {
                /* Address search (IP, MAC, CIDR) */
                QString src = QString::fromUtf8(pair->src_addr);
                QString dst = QString::fromUtf8(pair->dst_addr);

                bool src_match = is_cidr ? ipv4_in_cidr(src, trimmed) : src.contains(trimmed, Qt::CaseInsensitive);
                bool dst_match = is_cidr ? ipv4_in_cidr(dst, trimmed) : dst.contains(trimmed, Qt::CaseInsensitive);
                match = src_match || dst_match;

                if (match) {
                    if (src_match) highlighted_labels.insert(src);
                    if (dst_match) highlighted_labels.insert(dst);
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

    /* Start blink timer if we have matches; enable/disable Select Results */
    if (!m_highlightedPairItems.isEmpty()) {
        m_pairListBlinkTimer->start(500);
        m_selectSearchBtn->setEnabled(true);
    } else {
        m_selectSearchBtn->setEnabled(false);
    }

    if (m_circleWidget) {
        m_circleWidget->setHighlightedLabels(highlighted_labels);
    }
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
        if (!list_item)
            continue;
        
        /* Check checkbox state - linked pairs will have synced states */
        if (list_item->checkState() == Qt::Checked) {
            comm_pair_t *pair = (comm_pair_t *)list_item->data(Qt::UserRole).value<void*>();
            if (pair) {
                visible_pairs.insert(pair);
            }
        }
    }
    
    /* Update circle widget with visible pairs */
    if (m_circleWidget) {
        m_circleWidget->setVisiblePairs(visible_pairs);
    }
}

void MainWindow::onPairListItemChanged(QListWidgetItem *item)
{
    if (!item)
        return;
    
    /* If this item is linked to another, handle bidirectional behavior */
    if (m_linkedPairs.contains(item)) {
        QListWidgetItem *linked_item = m_linkedPairs[item];
        Qt::CheckState current_state = item->checkState();
        Qt::CheckState linked_state = linked_item->checkState();
        
        /* Temporarily disconnect signal to prevent infinite loop */
        disconnect(m_pairListWidget, &QListWidget::itemChanged, this, &MainWindow::onPairListItemChanged);
        
        /* Smart linking logic:
         * - When DESELECTING: If both are selected, deselect both (linked behavior)
         * - When SELECTING: If both are deselected, only select the clicked one (independent behavior)
         * - If states differ, sync to current state (for Select All/None operations)
         */
        if (current_state == Qt::Unchecked) {
            /* Deselecting: If linked is also checked, deselect it too */
            if (linked_state == Qt::Checked) {
                linked_item->setCheckState(Qt::Unchecked);
            }
        } else if (current_state == Qt::Checked) {
            /* Selecting: Only sync if linked is also being selected (from Select All) */
            /* Don't auto-select linked when user manually selects one direction */
            /* This allows independent selection for filtering purposes */
        }
        
        connect(m_pairListWidget, &QListWidget::itemChanged, this, &MainWindow::onPairListItemChanged);
    }
    
    /* Sync table checkboxes to match */
    syncTableCheckboxesFromPairList();
    
    /* Update visible pairs */
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
    
    /* Find the matching pair list item and update its check state */
    disconnect(m_pairListWidget, &QListWidget::itemChanged, this, &MainWindow::onPairListItemChanged);
    
    for (int i = 0; i < m_pairListWidget->count(); i++) {
        QListWidgetItem *list_item = m_pairListWidget->item(i);
        if (!list_item)
            continue;
        comm_pair_t *list_pair = (comm_pair_t *)list_item->data(Qt::UserRole).value<void*>();
        if (list_pair == pair) {
            list_item->setCheckState(checked ? Qt::Checked : Qt::Unchecked);
            
            /* Handle linked pair (bidirectional deselection) */
            if (!checked && m_linkedPairs.contains(list_item)) {
                QListWidgetItem *linked = m_linkedPairs[list_item];
                linked->setCheckState(Qt::Unchecked);
                /* Also uncheck the linked pair's table checkbox */
                comm_pair_t *linked_pair = (comm_pair_t *)linked->data(Qt::UserRole).value<void*>();
                if (linked_pair) {
                    for (auto it = m_tableCheckboxes.begin(); it != m_tableCheckboxes.end(); ++it) {
                        if (it.value() == linked_pair) {
                            it.key()->setChecked(false);
                            break;
                        }
                    }
                }
            }
            break;
        }
    }
    
    connect(m_pairListWidget, &QListWidget::itemChanged, this, &MainWindow::onPairListItemChanged);
    updateVisiblePairsFromWidgets();
    
    syncing = false;
}

void MainWindow::syncTableCheckboxesFromPairList()
{
    /* Sync table checkboxes to match pair list state */
    for (auto it = m_tableCheckboxes.begin(); it != m_tableCheckboxes.end(); ++it) {
        QCheckBox *checkbox = it.key();
        comm_pair_t *pair = it.value();
        
        /* Find matching pair list item */
        bool is_checked = false;
        for (int i = 0; i < m_pairListWidget->count(); i++) {
            QListWidgetItem *list_item = m_pairListWidget->item(i);
            if (!list_item) continue;
            comm_pair_t *list_pair = (comm_pair_t *)list_item->data(Qt::UserRole).value<void*>();
            if (list_pair == pair) {
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
    
    /* Update circle widget filter */
    if (m_circleWidget) {
        m_circleWidget->setProtocolFilter(enabled_protocols);
    }
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
    
    /* Update circle widget filter */
    if (m_circleWidget) {
        m_circleWidget->setProtocolFilter(enabled_protocols);
    }
}

/* =====================================================
 * ConnectionPopup implementation
 * =====================================================
 */

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

ConnectionPopup::ConnectionPopup(comm_pair_t *pair, comm_pair_t *reversePair, gboolean useMAC, QWidget *parent)
    : QWidget(parent, Qt::Popup | Qt::FramelessWindowHint)
    , m_pair(pair)
    , m_reversePair(reversePair)
    , m_useMAC(useMAC)
    , m_table(nullptr)
    , m_autoCloseTimer(nullptr)
    , m_headerLabel(nullptr)
    , m_contextMenuActive(false)
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

    /* Header: Source <-> Destination */
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
    layout->addWidget(m_headerLabel);

    /* Table */
    m_table = new QTableWidget(this);
    m_table->setColumnCount(5);
    m_table->setHorizontalHeaderLabels(QStringList() << "Protocol" << "Port" << "Service" << "Packets" << "% of Total");
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
            "QTableWidget::item:alternate {"
            "  background: #383838;"
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
            "QTableWidget::item:alternate {"
            "  background: #f5f5f5;"
            "}"
        );
    }

    connect(m_table, &QTableWidget::customContextMenuRequested, this, &ConnectionPopup::showContextMenu);

    layout->addWidget(m_table);

    /* Populate table with port summary data */
    populateTable();

    /* Auto-close timer: starts on leaveEvent, cancelled on enterEvent */
    m_autoCloseTimer = new QTimer(this);
    m_autoCloseTimer->setSingleShot(true);
    m_autoCloseTimer->setInterval(1000);  /* 1 second grace period */
    connect(m_autoCloseTimer, &QTimer::timeout, this, [this]() {
        if (m_contextMenuActive) return;   /* Don't destroy while menu is open */
        hide();
        deleteLater();
    });

    /* Size based on content */
    int rows = m_table->rowCount();
    int tableHeight = qMin(rows * 30 + 40, 300);
    resize(480, tableHeight + 60);
}

ConnectionPopup::~ConnectionPopup()
{
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

void ConnectionPopup::showContextMenu(const QPoint &pos)
{
    int row = m_table->rowAt(pos.y());
    if (row < 0 || row >= m_rowData.size())
        return;

    m_table->selectRow(row);

    QMenu menu(this);
    if (isDarkTheme()) {
        menu.setStyleSheet(
            "QMenu {"
            "  background: #2b2b2b;"
            "  color: #e0e0e0;"
            "  border: 1px solid #555;"
            "  padding: 4px;"
            "}"
            "QMenu::item {"
            "  padding: 6px 20px;"
            "}"
            "QMenu::item:selected {"
            "  background: #0078d4;"
            "  color: white;"
            "}"
            "QMenu::item:disabled {"
            "  color: #666;"
            "}"
        );
    }
    /* Light theme: no custom stylesheet — use native platform menu */

    QAction *filterAction = menu.addAction("Apply Filter in Wireshark");
    QAction *followAction = menu.addAction("Follow TCP Stream");
    menu.addSeparator();
    QAction *throughputAction = menu.addAction("TCP Throughput Graph");
    QAction *rttAction = menu.addAction("TCP Round-Trip Time Graph");

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

    /* Guard: prevent auto-close timer and leaveEvent from destroying us
     * while QMenu::exec()'s nested event loop is running.                  */
    m_contextMenuActive = true;
    m_autoCloseTimer->stop();

    QAction *selected = menu.exec(m_table->viewport()->mapToGlobal(pos));

    m_contextMenuActive = false;

    if (selected == filterAction) {
        applyFilterForRow(row);
    } else if (selected == followAction) {
        followTCPStreamForRow(row);
    } else if (selected == throughputAction) {
        openTcpStreamGraph(row, "Throughput");
    } else if (selected == rttAction) {
        openTcpStreamGraph(row, "Round Trip Time");
    } else {
        /* User dismissed without selecting; restart auto-close */
        m_autoCloseTimer->start();
    }
}

QString ConnectionPopup::buildFilterForRow(int row)
{
    if (row < 0 || row >= m_rowData.size() || !m_pair)
        return QString();

    const RowData &rd = m_rowData[row];
    
    /* Always use raw addresses for filter construction */
    QString src = QString::fromUtf8(m_pair->src_addr);
    QString dst = QString::fromUtf8(m_pair->dst_addr);

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
    plugin_if_apply_filter(filterBytes.constData(), true);
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

    hide();
    deleteLater();
}
