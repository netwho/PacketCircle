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

#ifndef UI_MAIN_WINDOW_H
#define UI_MAIN_WINDOW_H

#include <QMainWindow>
#include <QWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QCheckBox>
#include <QRadioButton>
#include <QButtonGroup>
#include <QListWidget>
#include <QLabel>
#include <QGroupBox>
#include <QTableWidget>
#include <QSplitter>
#include <QStackedWidget>
#include <QAbstractItemView>
#include <QLineEdit>
#include <QTimer>
#include <QMenu>
#include <QEnterEvent>
#include <QSettings>
#include <QTextEdit>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QCloseEvent>
#include <QPointer>
#include <QProgressBar>
#include <QFormLayout>
#include <QDialogButtonBox>
#include <QSpinBox>
#include <QDoubleSpinBox>
#include <QComboBox>
#include <QDesktopServices>
#include <QUrl>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QHttpMultiPart>
#include <QSslConfiguration>
#include <QSslError>
#include <QJsonDocument>
#include <QJsonObject>
#include "circle_widget.h"
#include "graph_widget.h"
#include "packet_analyzer.h"

/* Connection popup - shown when clicking a line in the circle view */
class ConnectionPopup : public QWidget
{
    Q_OBJECT

public:
    ConnectionPopup(comm_pair_t *pair, comm_pair_t *reversePair, gboolean useMAC, QWidget *parent = nullptr);
    ~ConnectionPopup();

    /* Called from the table view right-click menu to open a protocol info
     * dialog directly without first displaying the popup window itself.   */
    void triggerInfoForPort(quint16 port, int protoId);
    void triggerTransportDetails(bool forTcp);

    /* Performance flags — call after construction, before show() */
    void setPerformanceFlags(bool enableL2, bool enableTransport, bool enableDeep) {
        m_enableL2Analysis     = enableL2;
        m_enableTransportStats = enableTransport;
        m_enableDeepInspection = enableDeep;
    }

    /** Attach graph-view health/anomaly scores and connection metrics to the popup.
     *  Shows a "Score" button in the header that opens a breakdown dialog.
     *  responseTimeMs: first-packet RTT in ms (−1 = unavailable).
     *  throughputBps:  combined bytes/sec (0 = unavailable). */
    void setGraphScores(qreal healthScore, qreal anomalyScore,
                        const QList<GraphWidget::ScoreFactor> &healthFactors,
                        const QList<GraphWidget::ScoreFactor> &anomalyFactors,
                        qreal responseTimeMs    = -1.0,
                        qreal throughputBps     =  0.0,
                        guint32 winMin          = G_MAXUINT32,
                        guint32 winMax          = 0,
                        gdouble winAvg          = 0.0,
                        guint32 zeroWinCount    = 0,
                        gdouble zeroWinMaxDurMs = 0.0);
    void showScoreBtnCalculating(); /**< Show button as disabled "Calculating…" before scores arrive */

protected:
    void enterEvent(QEnterEvent *event) override;
    void leaveEvent(QEvent *event) override;

private:
    void populateTable();
    void populateWifiInfo();
    void showContextMenu(const QPoint &pos);
    void showWifiContextMenu(const QPoint &pos);
    void applyFilterForRow(int row);
    void applyWifiFilter();
    void followTCPStreamForRow(int row);
    void openTcpStreamGraph(int row, const QString &graphName);
    void showTlsInfoForRow(int row);
    void showHttpInfoForRow(int row);
    void showSmbInfoForRow(int row);
    void showKerberosInfoForRow(int row);
    void showEmailInfoForRow(int row);
    void showSqlInfoForRow(int row);
    void showVoipInfoForRow(int row);
    /* Layer-2 info dialogs */
    void populateL2Info();
    void loadL2Extended();
    void populateMacTable();
    void showL2ContextMenu(const QPoint &pos);
    void showL2InfoDialog();
    void showStpInfoDialog();
    void showLldpInfoDialog();
    void showLacpInfoDialog();
    void showEapInfoDialog();
    void showMacsecInfoDialog();
    void showArpInfoDialog();
    void showVlanInfoDialog();
    void showDhcpInfoForRow(int row);
    void showDnsInfoForRow(int row);
    void showLdapInfoForRow(int row);
    void showSnmpInfoForRow(int row);
    void showSyslogInfoForRow(int row);
    void showSshInfoForRow(int row);
    void showFtpInfoForRow(int row);
    void showTelnetInfoForRow(int row);
    void showNbnsInfoForRow(int row);
    void showNbdgmInfoForRow(int row);
    void showNbssInfoForRow(int row);
    void showTcpStatInfoForRow(int row);
    void showUdpStatInfoForRow(int row);
    void showProtocolInfoBrowserForRow(int row);
    void onMacTableContextMenu(const QPoint &pos);
    static bool isLayer2Protocol(const gchar *proto);
    QString buildFilterForRow(int row);
    static QString wifiPhyName(guint8 phy);
    static QString wifiReasonCodeText(guint16 reason);

    comm_pair_t *m_pair;        /* Primary pair (clicked direction) */
    comm_pair_t *m_reversePair; /* Reverse direction (may be NULL) */
    gboolean m_useMAC;
    bool m_enableL2Analysis     = true;
    bool m_enableTransportStats = true;
    bool m_enableDeepInspection = true;
    QTableWidget *m_table;
    QTableWidget  *m_macTable;        /* Protocol breakdown table for MAC/L2 mode */
    QProgressBar  *m_macProgressBar;  /* Indeterminate busy bar shown while scanning */
    QTextEdit *m_wifiInfoEdit;  /* Rich-text Wi-Fi detail card (used instead of table) */
    QTextEdit *m_l2InfoEdit;    /* Rich-text Layer-2 detail card for non-IP MAC pairs */
    QTimer *m_autoCloseTimer;
    QLabel *m_headerLabel;
    bool m_contextMenuActive;

    /* Graph-view score breakdown (optional — shown when coming from Graph view) */
    QPushButton                    *m_scoreBtn;
    qreal                           m_graphHealthScore;
    qreal                           m_graphAnomalyScore;
    qreal                           m_graphResponseTimeMs; /* −1 = unavailable */
    qreal                           m_graphThroughputBps;  /*  0 = unavailable */
    QList<GraphWidget::ScoreFactor> m_healthFactors;
    QList<GraphWidget::ScoreFactor> m_anomalyFactors;
    /* Pre-computed from m_pair at setGraphScores() time — safe to read in the lambda */
    qreal   m_rttMin          = -1.0;
    qreal   m_rttAvg          = -1.0;
    qreal   m_rttMax          = -1.0;
    qreal   m_fwdBps          =  0.0;
    qreal   m_revBps          =  0.0;
    bool    m_hasTcpData      = false;
    guint32 m_winMin          = G_MAXUINT32;
    guint32 m_winMax          = 0;
    gdouble m_winAvg          = 0.0;
    guint32 m_zeroWinCount    = 0;
    gdouble m_zeroWinMaxDurMs = 0.0;

    /* Per-row data (with per-port protocol information) — IP mode */
    struct RowData {
        QString protocol;  /* "TCP", "UDP", or "TCP+UDP" */
        quint16 port;
        quint64 packets;
        bool isTcp;        /* TRUE if TCP was seen on this specific port */
        bool isUdp;        /* TRUE if UDP was seen on this specific port */
    };
    QList<RowData> m_rowData;

    /* Per-row data for MAC/L2 protocol breakdown table */
    struct MacRowData {
        QString  etherType;    /* "0x0800" for EtherType rows, "802.3" for LLC rows */
        QString  sapSnap;      /* "0x42/0x42" for LLC rows, "—" for EtherType rows */
        QString  name;         /* "IPv4", "ARP", "STP / Spanning Tree", etc. */
        quint64  packets;
        bool     isEtherType;  /* true = Ethernet II EtherType; false = IEEE 802.3 LLC */
        guint16  etherTypeVal; /* numeric EtherType (0 for LLC rows) */
        guint8   dsap;         /* LLC DSAP (0 for EtherType rows) */
        guint8   ssap;         /* LLC SSAP (0 for EtherType rows) */
    };
    QList<MacRowData> m_macRowData;
};

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

    void updateAnalysis(analysis_result_t *result);
    gboolean getUseMAC() const { return m_useMAC; }

public slots:
    void onTop10Clicked();
    void onTop25Clicked();
    void onTop50Clicked();
    void onPacketsToggled(bool checked);
    void onBytesToggled(bool checked);
    void onLineThicknessToggled(bool checked);
    void onCircleViewToggled(bool checked);
    void onTableViewToggled(bool checked);
    void onMACToggled(bool checked);
    void onIPToggled(bool checked);
    void onSelectAllClicked();
    void onSelectSearchResultsClicked();
    void onSelectNoneClicked();
    void onInvertPairSelection();
    void onApplyFilterClicked();
    void onClearFilterClicked();
    void onReloadDataClicked();
    void onPairSelectionChanged(QList<comm_pair_t*> selected);
    void onNodeVisibilityToggle(QList<comm_pair_t*> pairs, bool enable);
    void onPairListItemChanged(QListWidgetItem *item);
    void onProtocolCheckboxToggled(const QString &protocol, bool checked);
    void onProtocolCategoryToggled(const QString &category, const QStringList &protocols, bool checked);
    void onTableCheckboxToggled(comm_pair_t *pair, bool checked);
    void updateVisiblePairsFromWidgets();
    void syncTableCheckboxesFromPairList();
    void onHelpClicked();
    void onSavePDFClicked();
    void onSendToNtopClicked();
    void onSendToMalcolmClicked();
    void onLineClicked(comm_pair_t *pair, const QPoint &globalPos);
    void onLineHovered(comm_pair_t *pair);
    void onPairListBlinkTimer();
    void onTableCellClicked(int row, int col);
    void onTableContextMenu(const QPoint &pos);
    void onGraphViewToggled(bool checked);
    void onGraphEdgeColorChanged(int index);
    void onGraphNodeColorChanged(int index);
    void onGraphLayoutChanged(int index);
    void onGraphRelayout();
    void onGraphLegendFilter(QList<comm_pair_t*> matchingPairs, bool active);
    void onPairListContextMenu(const QPoint &pos);

protected:
    void resizeEvent(QResizeEvent *event) override;
    void closeEvent(QCloseEvent *event) override;
    bool eventFilter(QObject *obj, QEvent *event) override;

private:
    void setupUI();
    void createControls();
    void createCircleView();
    void createTableView();
    void createLegend();
    void updateViews();
    void updateLegend();
    void relayoutControls();
    QString createFilterString();
    QList<comm_pair_t*> getActivePairsForFilter() const;
    void applySearchFilter(const QString &query);
    void applyAsDisplayFilter(const QString &filter);
    void enterSearchOverrideMode(const QList<comm_pair_t*> &matches, const QString &query);
    void exitSearchOverrideMode();
    void showSearchHelp();
    void refreshPairListText();
    void updateSearchBarForMode();
    static QString truncateIPv6Address(const QString &address);
    static bool isMACAddress(const QString &address);
    void savePreferences();
    void loadPreferences();
    QString preferencesFilePath() const;
    void saveThresholdGroups();
    void loadThresholdGroups();
    void showThresholdGroupEditor(const QString &groupName = QString());
    void saveWifiThresholdGroups();
    void loadWifiThresholdGroups();
    void showWifiThresholdGroupEditor(const QString &groupName = QString());
    bool showNtopngConfigDialog();
    bool showMalcolmConfigDialog();
    void showSettingsDialog(int initialPage = 0);
    void showIntegrationDialog();
    void showInternalNetworksDialog();
    void showPerformanceDialog();
    void showGraphThresholdsDialog();
    void showWifiThresholdsDialog();
    void showResetSettingsDialog();
    void showAboutDialog();
    void showReportConfigDialog();
    void showCaCertConfigDialog();
    void uploadToNtopng(const QString &filePath, const QString &host, int port,
                        bool useHttps, const QString &username, const QString &password,
                        bool ignoreSslErrors, const QString &caCertPath);
    void uploadToMalcolm(const QString &filePath, const QString &host, int port,
                         bool useHttps, const QString &username, const QString &password,
                         bool ignoreSslErrors, quint32 startTime, quint32 stopTime);

    /* UI Components */
    QWidget *m_centralWidget;
    QVBoxLayout *m_mainLayout;
    QWidget *m_controlsWidget;          /* Controls container */
    QVBoxLayout *m_controlsOuterLayout; /* Outer layout for controls rows */
    QHBoxLayout *m_controlsRow1;        /* Row 1: view/data options */
    QHBoxLayout *m_controlsRow2;        /* Row 2: actions + search */
    QWidget *m_row1Widget;
    QWidget *m_row2Widget;
    
    /* Control buttons */
    QPushButton *m_top10Btn;
    QPushButton *m_top25Btn;
    QPushButton *m_top50Btn;
    QPushButton *m_packetsBtn;
    QPushButton *m_bytesBtn;
    QPushButton *m_circleBtn;
    QPushButton *m_tableBtn;
    QPushButton *m_graphBtn;
    QPushButton *m_macBtn;
    QPushButton *m_ipBtn;
    QPushButton *m_applyFilterBtn;
    QPushButton *m_clearFilterBtn;
    QPushButton *m_reloadDataBtn;
    QPushButton *m_savePDFBtn;
    QPushButton *m_sendToNtopBtn;
    QPushButton *m_sendToMalcolmBtn;
    QPushButton *m_settingsBtn;
    bool         m_ntopEnabled;
    bool         m_malcolmEnabled;

    /* Main splitter */
    QSplitter *m_splitter;
    bool m_splitterSizesRestored;  /* true if user had saved splitter sizes */

    /* Graph controls row (Row 3, shown only in Graph mode) */
    QWidget   *m_graphControlsRow;
    QComboBox *m_graphEdgeColorCombo;
    QComboBox *m_graphNodeColorCombo;
    QComboBox *m_graphLayoutCombo;

    /* Views */
    QStackedWidget *m_viewStack;
    CircleWidget *m_circleWidget;
    QWidget *m_circleContainer;
    GraphWidget *m_graphWidget;
    QLineEdit *m_searchLineEdit;
    QTableWidget *m_tableWidget;
    QListWidget *m_pairListWidget;
    QWidget *m_pairListContainer;  /* Container for pair list and legend */
    QMap<QListWidgetItem*, QListWidgetItem*> m_linkedPairs;  /* Map to link bidirectional pair checkboxes */
    QMap<QCheckBox*, comm_pair_t*> m_tableCheckboxes;  /* Map table checkboxes to pairs for sync */

    /* Legend */
    QWidget *m_legendWidget;
    QHBoxLayout *m_legendLayout;      /* First row layout for legend (kept for compatibility) */
    QHBoxLayout *m_legendRow2Layout;  /* Second row layout for legend */
    QHash<QString, QCheckBox*> m_protocolCheckboxes;  /* Protocol checkboxes for filtering */
    QCheckBox *m_lineThicknessCheckBox;

    /* Search blinking */
    QTimer *m_pairListBlinkTimer;
    bool m_pairListBlinkState;
    QList<int> m_highlightedPairItems;  /* Indices of highlighted items in pair list */
    QListWidgetItem *m_hoveredPairListItem;  /* Item currently highlighted by hover */

    /* Connection popup */
    QPointer<ConnectionPopup> m_connectionPopup;

    /* ntopng network manager */
    QNetworkAccessManager *m_networkManager;

    /* Data */
    analysis_result_t *m_analysisResult;
    GList *m_top_pairs;  /* Track top pairs list to free it properly */
    GList *m_circle_pairs;  /* Limited list for circle widget (exactly top_n pairs) */
    /* Search override mode: shows full-buffer matches instead of Top-N ranked pairs.
     * Active from user confirmation until search is cleared or a Top-N button is clicked. */
    GList *m_searchOverridePairs; /* borrowed from m_analysisResult — do NOT free elements */
    bool   m_searchOverrideMode;
    guint  m_savedTopN;           /* m_topN saved before entering override mode */
    guint m_topN;
    gboolean m_useBytes;
    gboolean m_useMAC;
    bool m_darkTheme;
    bool m_wifiMode;

    /* Beta features */
    bool m_betaGraphEnabled;     /* Graph view unlocked via [Beta] EnableGraphView=true in settings.ini */

    /* Performance settings (Tier 2) */
    bool m_enableL2Analysis;     /* Layer-2/LLC deep scan enabled (default: true) */
    bool m_enableTransportStats; /* TCP/UDP Transport Details scan enabled (default: true) */
    bool m_enableDeepInspection; /* Protocol info dialogs (TLS/HTTP/SMB/…) enabled (default: true) */
    QList<comm_pair_t*> m_selectedPairs;

    /* Graph threshold groups */
    QList<GraphWidget::GraphThresholds> m_thresholdGroups; /* index 0 = Default (read-only) */
    int                                 m_activeThresholdGroup; /* index into m_thresholdGroups */
    QList<GraphWidget::InternalSubnet>  m_internalSubnets;

    /* WiFi signal-quality threshold groups */
    QList<CircleWidget::WifiThresholds> m_wifiThresholdGroups; /* index 0 = Default (read-only) */
    int                                 m_activeWifiThresholdGroup;

    /* Report configuration */
    QString m_reportCompany;
    QString m_reportPreparedBy;
    QString m_reportProject;
    QString m_reportComments;
    int     m_reportPaperSize; /* 0 = A4, 1 = Legal */
};

#endif /* UI_MAIN_WINDOW_H */
