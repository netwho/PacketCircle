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
#include <QDir>
#include <QFile>
#include <QCloseEvent>
#include <QPointer>
#include "circle_widget.h"
#include "packet_analyzer.h"

/* Connection popup - shown when clicking a line in the circle view */
class ConnectionPopup : public QWidget
{
    Q_OBJECT

public:
    ConnectionPopup(comm_pair_t *pair, comm_pair_t *reversePair, gboolean useMAC, QWidget *parent = nullptr);
    ~ConnectionPopup();

protected:
    void enterEvent(QEnterEvent *event) override;
    void leaveEvent(QEvent *event) override;

private:
    void populateTable();
    void showContextMenu(const QPoint &pos);
    void applyFilterForRow(int row);
    void followTCPStreamForRow(int row);
    void openTcpStreamGraph(int row, const QString &graphName);
    QString buildFilterForRow(int row);

    comm_pair_t *m_pair;        /* Primary pair (clicked direction) */
    comm_pair_t *m_reversePair; /* Reverse direction (may be NULL) */
    gboolean m_useMAC;
    QTableWidget *m_table;
    QTimer *m_autoCloseTimer;
    QLabel *m_headerLabel;
    bool m_contextMenuActive;

    /* Per-row data (with per-port protocol information) */
    struct RowData {
        QString protocol;  /* "TCP", "UDP", or "TCP+UDP" */
        quint16 port;
        quint64 packets;
        bool isTcp;        /* TRUE if TCP was seen on this specific port */
        bool isUdp;        /* TRUE if UDP was seen on this specific port */
    };
    QList<RowData> m_rowData;
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
    void onLineClicked(comm_pair_t *pair, const QPoint &globalPos);
    void onPairListBlinkTimer();

protected:
    void resizeEvent(QResizeEvent *event) override;
    void closeEvent(QCloseEvent *event) override;

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
    void refreshPairListText();
    void updateSearchBarForMode();
    static QString truncateIPv6Address(const QString &address);
    static bool isMACAddress(const QString &address);
    void savePreferences();
    void loadPreferences();
    QString preferencesFilePath() const;

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
    QPushButton *m_macBtn;
    QPushButton *m_ipBtn;
    QPushButton *m_selectAllBtn;
    QPushButton *m_selectSearchBtn;
    QPushButton *m_selectNoneBtn;
    QPushButton *m_applyFilterBtn;
    QPushButton *m_clearFilterBtn;
    QPushButton *m_reloadDataBtn;
    QPushButton *m_savePDFBtn;
    /* Help is now a menu bar action, no button member needed */

    /* Main splitter */
    QSplitter *m_splitter;
    bool m_splitterSizesRestored;  /* true if user had saved splitter sizes */

    /* Views */
    QStackedWidget *m_viewStack;
    CircleWidget *m_circleWidget;
    QWidget *m_circleContainer;
    QLineEdit *m_searchLineEdit;
    QLabel *m_searchLabel;
    QTableWidget *m_tableWidget;
    QListWidget *m_pairListWidget;
    QWidget *m_pairListContainer;  /* Container for pair list and legend */
    QMap<QListWidgetItem*, QListWidgetItem*> m_linkedPairs;  /* Map to link bidirectional pair checkboxes */
    QMap<QCheckBox*, comm_pair_t*> m_tableCheckboxes;  /* Map table checkboxes to pairs for sync */

    /* Legend */
    QWidget *m_legendWidget;
    QHBoxLayout *m_legendLayout;  /* First row layout for legend (kept for compatibility) */
    QHBoxLayout *m_legendRow2Layout;  /* Second row layout for legend */
    QHash<QString, QCheckBox*> m_protocolCheckboxes;  /* Protocol checkboxes for filtering */
    QCheckBox *m_lineThicknessCheckBox;

    /* Search blinking */
    QTimer *m_pairListBlinkTimer;
    bool m_pairListBlinkState;
    QList<int> m_highlightedPairItems;  /* Indices of highlighted items in pair list */

    /* Connection popup */
    QPointer<ConnectionPopup> m_connectionPopup;

    /* Data */
    analysis_result_t *m_analysisResult;
    GList *m_top_pairs;  /* Track top pairs list to free it properly */
    GList *m_circle_pairs;  /* Limited list for circle widget (exactly top_n pairs) */
    guint m_topN;
    gboolean m_useBytes;
    gboolean m_useMAC;
    bool m_darkTheme;
    QList<comm_pair_t*> m_selectedPairs;
};

#endif /* UI_MAIN_WINDOW_H */
