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
#include <algorithm>
#include <epan/plugin_if.h>

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
    , m_controlsLayout(nullptr)
    , m_top10Btn(nullptr)
    , m_top25Btn(nullptr)
    , m_top50Btn(nullptr)
    , m_packetsRadio(nullptr)
    , m_bytesRadio(nullptr)
    , m_circleRadio(nullptr)
    , m_tableRadio(nullptr)
    , m_macRadio(nullptr)
    , m_ipRadio(nullptr)
    , m_selectAllBtn(nullptr)
    , m_selectNoneBtn(nullptr)
    , m_applyFilterBtn(nullptr)
    , m_clearFilterBtn(nullptr)
    , m_savePDFBtn(nullptr)
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
    , m_analysisResult(NULL)
    , m_top_pairs(NULL)
    , m_circle_pairs(NULL)
    , m_topN(10)
    , m_useBytes(FALSE)
    , m_useMAC(FALSE)
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
    QSplitter *splitter = new QSplitter(Qt::Horizontal, this);
    splitter->addWidget(m_viewStack);
    splitter->addWidget(m_pairListContainer);
    
    /* Set stretch factors - circle area stretches more, pair list less */
    splitter->setStretchFactor(0, 1);  /* Circle container - takes extra space */
    splitter->setStretchFactor(1, 0);  /* Pair list container - stays near its size */
    
    /* Make splitter handle visible and easy to grab on all platforms */
#ifdef Q_OS_WIN
    splitter->setHandleWidth(8);
    splitter->setStyleSheet(
        "QSplitter::handle { background-color: #ccc; }"
        "QSplitter::handle:hover { background-color: #aaa; }"
    );
#else
    splitter->setHandleWidth(5);
#endif
    splitter->setChildrenCollapsible(false);
    
    /* Set initial sizes: give pair list 450px, rest to circle */
    splitter->setSizes(QList<int>() << 950 << 450);

    /* Refresh MAC address display when the pair list panel is resized */
    connect(splitter, &QSplitter::splitterMoved, this, &MainWindow::refreshPairListText);

    m_mainLayout->addWidget(splitter);
    
    /* Set initial view */
    m_circleRadio->setChecked(true);
    m_viewStack->setCurrentIndex(0);
    
    /* Make window resizable with a reasonable minimum size */
    setMinimumSize(1500, 800);
    resize(1600, 900);
    
    /* Set window title and flags */
    setWindowTitle("PacketCircle");
    setWindowFlags(windowFlags() | Qt::WindowContextHelpButtonHint);
    
    /* Note: Qt::WindowContextHelpButtonHint adds a help button to the title bar on some platforms */
    /* If not available, the Help button in controls will be used */
}

void MainWindow::createControls()
{
    QGroupBox *controlsGroup = new QGroupBox("Controls", this);
    m_controlsLayout = new QHBoxLayout(controlsGroup);
    m_controlsLayout->setSpacing(4);
    m_controlsLayout->setContentsMargins(6, 2, 6, 2);

    /* Top N buttons */
    m_top10Btn = new QPushButton("Top 10", this);
    m_top25Btn = new QPushButton("Top 25", this);
    m_top50Btn = new QPushButton("Top 50", this);
    m_top10Btn->setCheckable(true);
    m_top25Btn->setCheckable(true);
    m_top50Btn->setCheckable(true);
    m_top10Btn->setChecked(true);

    connect(m_top10Btn, &QPushButton::clicked, this, &MainWindow::onTop10Clicked);
    connect(m_top25Btn, &QPushButton::clicked, this, &MainWindow::onTop25Clicked);
    connect(m_top50Btn, &QPushButton::clicked, this, &MainWindow::onTop50Clicked);

    /* Packets/Bytes radio */
    QButtonGroup *volumeGroup = new QButtonGroup(this);
    m_packetsRadio = new QRadioButton("Packets", this);
    m_bytesRadio = new QRadioButton("Bytes", this);
    m_packetsRadio->setChecked(true);
    volumeGroup->addButton(m_packetsRadio);
    volumeGroup->addButton(m_bytesRadio);

    connect(m_packetsRadio, &QRadioButton::toggled, this, &MainWindow::onPacketsToggled);
    connect(m_bytesRadio, &QRadioButton::toggled, this, &MainWindow::onBytesToggled);

    /* View type radio */
    QButtonGroup *viewGroup = new QButtonGroup(this);
    m_circleRadio = new QRadioButton("Circle", this);
    m_tableRadio = new QRadioButton("Table", this);
    m_circleRadio->setChecked(true);
    viewGroup->addButton(m_circleRadio);
    viewGroup->addButton(m_tableRadio);

    connect(m_circleRadio, &QRadioButton::toggled, this, &MainWindow::onCircleViewToggled);
    connect(m_tableRadio, &QRadioButton::toggled, this, &MainWindow::onTableViewToggled);

    /* MAC/IP radio */
    QButtonGroup *addrGroup = new QButtonGroup(this);
    m_macRadio = new QRadioButton("MAC", this);
    m_ipRadio = new QRadioButton("IP", this);
    m_ipRadio->setChecked(true);
    addrGroup->addButton(m_macRadio);
    addrGroup->addButton(m_ipRadio);

    connect(m_macRadio, &QRadioButton::toggled, this, &MainWindow::onMACToggled);
    connect(m_ipRadio, &QRadioButton::toggled, this, &MainWindow::onIPToggled);

    /* Selection buttons */
    m_selectAllBtn = new QPushButton("Select All", this);
    m_selectNoneBtn = new QPushButton("Select None", this);
    m_applyFilterBtn = new QPushButton("Filter", this);
    m_clearFilterBtn = new QPushButton("Clear Filter", this);
    m_clearFilterBtn->setToolTip("Clear Wireshark display filter and show all connections");
    m_reloadDataBtn = new QPushButton("Reload Data", this);
    m_savePDFBtn = new QPushButton("PDF", this);
    m_savePDFBtn->setToolTip("Save report as PDF with circle visualization and IP pair list");
    
    /* Help button - styled like other control buttons */
    QPushButton *helpBtn = new QPushButton("Help", this);
    helpBtn->setToolTip("Show help and controls description");
    connect(helpBtn, &QPushButton::clicked, this, &MainWindow::onHelpClicked);
    
    /* Line weight toggle */
    m_lineThicknessCheckBox = new QCheckBox("Weight", this);
    m_lineThicknessCheckBox->setChecked(false);  /* Disabled by default */
    connect(m_lineThicknessCheckBox, &QCheckBox::toggled, this, &MainWindow::onLineThicknessToggled);

    connect(m_selectAllBtn, &QPushButton::clicked, this, &MainWindow::onSelectAllClicked);
    connect(m_selectNoneBtn, &QPushButton::clicked, this, &MainWindow::onSelectNoneClicked);
    connect(m_applyFilterBtn, &QPushButton::clicked, this, &MainWindow::onApplyFilterClicked);
    connect(m_clearFilterBtn, &QPushButton::clicked, this, &MainWindow::onClearFilterClicked);
    connect(m_reloadDataBtn, &QPushButton::clicked, this, &MainWindow::onReloadDataClicked);
    connect(m_savePDFBtn, &QPushButton::clicked, this, &MainWindow::onSavePDFClicked);

    /* Add to layout */
    m_controlsLayout->addWidget(m_top10Btn);
    m_controlsLayout->addWidget(m_top25Btn);
    m_controlsLayout->addWidget(m_top50Btn);
    m_controlsLayout->addWidget(m_lineThicknessCheckBox);
    m_controlsLayout->addWidget(new QLabel("|", this));
    m_controlsLayout->addWidget(m_packetsRadio);
    m_controlsLayout->addWidget(m_bytesRadio);
    m_controlsLayout->addWidget(new QLabel("|", this));
    m_controlsLayout->addWidget(m_circleRadio);
    m_controlsLayout->addWidget(m_tableRadio);
    m_controlsLayout->addWidget(new QLabel("|", this));
    m_controlsLayout->addWidget(m_macRadio);
    m_controlsLayout->addWidget(m_ipRadio);
    m_controlsLayout->addWidget(new QLabel("|", this));
    m_controlsLayout->addWidget(m_selectAllBtn);
    m_controlsLayout->addWidget(m_selectNoneBtn);
    m_controlsLayout->addWidget(m_applyFilterBtn);
    m_controlsLayout->addWidget(m_clearFilterBtn);
    m_controlsLayout->addWidget(new QLabel("|", this));
    m_controlsLayout->addWidget(m_reloadDataBtn);
    m_controlsLayout->addWidget(m_savePDFBtn);
    m_controlsLayout->addWidget(helpBtn);
    m_controlsLayout->addStretch();

    /* Set fixed minimum height for controls - width expands as needed */
    controlsGroup->setMinimumHeight(80);
    controlsGroup->setMaximumHeight(80);  /* Fixed height */
    controlsGroup->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);

    m_mainLayout->addWidget(controlsGroup);
}

void MainWindow::createCircleView()
{
    m_circleWidget = new CircleWidget(this);
    connect(m_circleWidget, &CircleWidget::pairSelectionChanged, 
            this, &MainWindow::onPairSelectionChanged);
    connect(m_circleWidget, &CircleWidget::nodeVisibilityToggle,
            this, &MainWindow::onNodeVisibilityToggle);

    m_circleContainer = new QWidget(this);
    QVBoxLayout *circleLayout = new QVBoxLayout(m_circleContainer);
    circleLayout->setContentsMargins(0, 0, 0, 0);
    circleLayout->setSpacing(6);

    circleLayout->addWidget(m_circleWidget, 1);

    QHBoxLayout *searchLayout = new QHBoxLayout();
    searchLayout->setContentsMargins(2, 0, 2, 2);
    m_searchLabel = new QLabel("Search IP", m_circleContainer);
    m_searchLineEdit = new QLineEdit(m_circleContainer);
    m_searchLineEdit->setPlaceholderText("Partial IP or CIDR (e.g., 192.168.1 or 10.0.0.0/24)");

    /* Explicit styling so the search bar is visible on all platforms/themes */
    m_searchLineEdit->setStyleSheet(
        "QLineEdit { background-color: white; color: black; border: 1px solid #999; "
        "padding: 2px 4px; }"
    );
    m_searchLabel->setStyleSheet("QLabel { color: palette(text); padding: 0 4px; }");

    connect(m_searchLineEdit, &QLineEdit::returnPressed, this, [this]() {
        applySearchFilter(m_searchLineEdit->text());
    });
    connect(m_searchLineEdit, &QLineEdit::textChanged, this, [this](const QString &text) {
        if (text.trimmed().isEmpty()) {
            applySearchFilter(QString());
        }
    });

    searchLayout->addWidget(m_searchLabel);
    searchLayout->addWidget(m_searchLineEdit, 1);
    circleLayout->addLayout(searchLayout);
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
    m_pairListWidget->setMinimumWidth(250);
    m_pairListWidget->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    
    /* Remove left padding/margins to minimize empty space - use stylesheet */
    m_pairListWidget->setStyleSheet(
        "QListWidget { "
        "    padding: 0px; "
        "    margin: 0px; "
        "    border: none; "
        "} "
        "QListWidget::item { "
        "    padding-left: 8px; "
        "    margin: 0px; "
        "    border: none; "
        "    height: 30px; "
        "} "
        "QListWidget::item:selected { "
        "    background-color: #3daee9; "
        "} "
        "QListWidget::item:hover { "
        "    background-color: #e0e0e0; "
        "}"
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
    m_pairListContainer->setMinimumWidth(250);
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

        m_tableWidget->setItem(row, 1, new QTableWidgetItem(pair->src_addr));
        m_tableWidget->setItem(row, 2, new QTableWidgetItem(pair->dst_addr));
        
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
                guint64 count = port_value ? *((guint64*)port_value) : 0;
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
    
    /* Find maximum source address length for alignment */
    guint max_src_len = 0;
    guint max_dst_len = 0;
    for (iter = m_top_pairs; iter; iter = iter->next) {
        comm_pair_t *pair = (comm_pair_t *)iter->data;
        if (!pair || !pair->src_addr || !pair->dst_addr)
            continue;
        guint src_len = (guint)strlen(pair->src_addr);
        guint dst_len = (guint)strlen(pair->dst_addr);
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
            
            QString src_addr = QString::fromUtf8(pair->src_addr);
            QString dst_addr = QString::fromUtf8(pair->dst_addr);
            
            /* Truncate IPv6 addresses to save space (first 4 hex digits ... last 4 hex digits) */
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
        color_label->setStyleSheet(QString("background-color: rgb(%1,%2,%3); min-width: 12px; min-height: 12px; max-width: 12px; max-height: 12px; border: 1px solid #666;")
                                   .arg(color.red()).arg(color.green()).arg(color.blue()));
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
        
        category_checkbox->setStyleSheet("QCheckBox { font-size: 9pt; } QCheckBox:disabled { color: #888; }");
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
    helpDialog->setWindowTitle("Help - PacketCircle");
    helpDialog->setMinimumSize(1000, 600);
    helpDialog->resize(1000, 700);
    /* Make dialog resizable */
    helpDialog->setSizeGripEnabled(true);
    
    QVBoxLayout *layout = new QVBoxLayout(helpDialog);
    
    /* Create QTextEdit for rich text display with proper sizing */
    QTextEdit *textEdit = new QTextEdit(helpDialog);
    textEdit->setReadOnly(true);
    textEdit->setMinimumWidth(950);
    textEdit->setMinimumHeight(600);
    
    /* Use plain text formatting - no bold for descriptions, only titles */
    textEdit->setHtml(
        "<style>"
        "h2 { font-weight: bold; margin-top: 10px; margin-bottom: 15px; }"
        "h3 { font-weight: bold; margin-top: 15px; margin-bottom: 10px; }"
        "p { font-weight: normal; margin-top: 8px; margin-bottom: 8px; line-height: 1.4; }"
        "li { font-weight: normal; margin-top: 6px; margin-bottom: 6px; }"
        "</style>"
        "<h2>PacketCircle Help</h2>"

        "<h3>Controls:</h3>"
        "<p style='margin-left: 0; padding-left: 0; font-weight: normal;'>"
        "• Top 10/25/50: Limit display to top N communication pairs<br/>"
        "• Weight: Enable/disable line weight variation based on traffic volume<br/>"
        "• Packets/Bytes: Sort pairs by packet count or byte count<br/>"
        "• Circle/Table: Switch between circular visualization and table view<br/>"
        "• MAC/IP: Display MAC address pairs or IP address pairs<br/>"
        "• Select All/None: Show or hide all communication pairs<br/>"
        "• Filter: Apply selected pairs as a Wireshark display filter (directional — filters by exact source→destination)<br/>"
        "• Clear Filter: Select all pairs, clear the Wireshark display filter, and show all packets<br/>"
        "• Reload Data: Re-analyze current capture file<br/>"
        "• PDF: Export a one-page PDF report containing the circle visualization and IP pair table<br/>"
        "• Search: Highlight nodes and pairs by partial IP address, CIDR notation (e.g. 10.0.0.0/8), or partial MAC address. "
        "The label switches between 'Search IP' and 'Search MAC' depending on the active mode."
        "</p>"

        "<h3>Filtering:</h3>"
        "<p style='font-weight: normal;'>The <b>Filter</b> button applies a Wireshark display filter for the currently checked pairs. "
        "Each pair is filtered by its exact direction — selecting only \"A → B\" will filter to packets where A is the source "
        "and B is the destination. To see both directions, check both \"A → B\" and \"B → A\".</p>"
        "<p style='font-weight: normal;'>The <b>Clear Filter</b> button resets everything: it selects all pairs in the list "
        "and sends an empty display filter to Wireshark so all packets are visible again.</p>"

        "<h3>Protocol Filter:</h3>"
        "<p style='font-weight: normal;'>The protocol legend at the bottom shows protocol categories with checkboxes:</p>"
        "<p style='margin-left: 0; padding-left: 0; font-weight: normal;'>"
        "• ARP: Address Resolution Protocol (ARP, RARP)<br/>"
        "• ICMP: Internet Control Message Protocol (ICMP, ICMPv6)<br/>"
        "• TCP: Transmission Control Protocol<br/>"
        "• UDP: User Datagram Protocol<br/>"
        "• Infrastructure: Routing and infrastructure protocols (OSPF, BGP, RIP, EIGRP, ISIS, IGMP, PIM, VRRP, HSRP, SCTP, DCCP)<br/>"
        "• Unknown: Unidentified or generic protocols (IP, IPv4, IPv6, Ethernet)"
        "</p>"
        "<p style='font-weight: normal;'>Uncheck a protocol category to hide its connections in the circle view. "
        "Protocols not found in the current capture show a dash (N/A) in the checkbox.</p>"
        "<p style='font-weight: normal;'>When a pair carries both TCP and UDP traffic, it is shown as an alternating "
        "dotted line with TCP and UDP colors. If you filter to only one protocol (e.g. uncheck UDP), the mixed pair "
        "will appear as a solid line in the selected protocol's color.</p>"

        "<h3>IP Pair List:</h3>"
        "<p style='font-weight: normal;'>Checkboxes control visibility of communication lines in the circle. "
        "Only checked pairs are drawn — unchecked pairs are completely hidden. "
        "Pairs with traffic in both directions (A→B and B→A) are shown adjacent to each other with linked checkboxes — "
        "deselecting one automatically deselects the other.</p>"
        "<p style='font-weight: normal;'>The splitter between the circle and the pair list can be dragged "
        "to resize the two panels.</p>"

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
    footerLabel->setStyleSheet("color: #888; font-size: 11px;");

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
        QString src = QString::fromUtf8(pair->src_addr);
        QString dst = QString::fromUtf8(pair->dst_addr);
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
                     QString("Generated by PacketCircle v0.2.2 — %1")
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
        m_searchLabel->setText("Search IP");
        m_searchLineEdit->setPlaceholderText("Partial IP or CIDR (e.g., 192.168.1 or 10.0.0.0/24)");
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

void MainWindow::refreshPairListText()
{
    if (!m_pairListWidget || m_pairListWidget->count() == 0)
        return;

    /* Check if any item is a MAC address */
    bool has_mac = false;
    for (int i = 0; i < m_pairListWidget->count(); i++) {
        QListWidgetItem *item = m_pairListWidget->item(i);
        comm_pair_t *pair = static_cast<comm_pair_t*>(item->data(Qt::UserRole).value<void*>());
        if (pair && pair->src_addr && isMACAddress(QString::fromUtf8(pair->src_addr))) {
            has_mac = true;
            break;
        }
    }
    if (!has_mac) return;  /* Only relevant in MAC mode */

    /* Determine available width for text */
    int listWidth = m_pairListWidget->viewport()->width();
    QFontMetrics fm(m_pairListWidget->font());
    /* A full MAC pair line: "aa:bb:cc:dd:ee:ff → aa:bb:cc:dd:ee:ff" + checkbox space */
    int fullMacWidth = fm.horizontalAdvance("aa:bb:cc:dd:ee:ff \xE2\x86\x92 aa:bb:cc:dd:ee:ff") + 50;
    bool showFull = (listWidth >= fullMacWidth);

    /* Find max address lengths for alignment */
    guint max_src_len = 0, max_dst_len = 0;
    for (int i = 0; i < m_pairListWidget->count(); i++) {
        QListWidgetItem *item = m_pairListWidget->item(i);
        comm_pair_t *pair = static_cast<comm_pair_t*>(item->data(Qt::UserRole).value<void*>());
        if (!pair || !pair->src_addr || !pair->dst_addr) continue;
        QString src = QString::fromUtf8(pair->src_addr);
        QString dst = QString::fromUtf8(pair->dst_addr);
        if (!showFull) {
            src = truncateIPv6Address(src);
            dst = truncateIPv6Address(dst);
        }
        if ((guint)src.length() > max_src_len) max_src_len = (guint)src.length();
        if ((guint)dst.length() > max_dst_len) max_dst_len = (guint)dst.length();
    }

    /* Update each item's text */
    for (int i = 0; i < m_pairListWidget->count(); i++) {
        QListWidgetItem *item = m_pairListWidget->item(i);
        comm_pair_t *pair = static_cast<comm_pair_t*>(item->data(Qt::UserRole).value<void*>());
        if (!pair || !pair->src_addr || !pair->dst_addr) continue;
        QString src = QString::fromUtf8(pair->src_addr);
        QString dst = QString::fromUtf8(pair->dst_addr);
        if (!showFull) {
            src = truncateIPv6Address(src);
            dst = truncateIPv6Address(dst);
        }
        src = src.leftJustified(max_src_len, ' ');
        dst = dst.leftJustified(max_dst_len, ' ');
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

void MainWindow::applySearchFilter(const QString &query)
{
    QString trimmed = query.trimmed();
    QSet<QString> highlighted_labels;

    if (trimmed.isEmpty()) {
        if (m_circleWidget) {
            m_circleWidget->setHighlightedLabels(highlighted_labels);
        }
        if (m_pairListWidget) {
            for (int i = 0; i < m_pairListWidget->count(); i++) {
                QListWidgetItem *list_item = m_pairListWidget->item(i);
                if (list_item)
                    list_item->setBackground(QBrush());
            }
        }
        return;
    }

    bool is_cidr = trimmed.contains('/') && parse_cidr(trimmed, nullptr, nullptr);

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

            QString src = QString::fromUtf8(pair->src_addr);
            QString dst = QString::fromUtf8(pair->dst_addr);

            bool src_match = is_cidr ? ipv4_in_cidr(src, trimmed) : src.contains(trimmed, Qt::CaseInsensitive);
            bool dst_match = is_cidr ? ipv4_in_cidr(dst, trimmed) : dst.contains(trimmed, Qt::CaseInsensitive);
            bool match = src_match || dst_match;

            if (match) {
                list_item->setBackground(QBrush(QColor(255, 248, 200)));
                if (src_match)
                    highlighted_labels.insert(src);
                if (dst_match)
                    highlighted_labels.insert(dst);
            } else {
                list_item->setBackground(QBrush());
            }
        }
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
