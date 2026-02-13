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
#include "circle_widget.h"
#include "packet_analyzer.h"

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

private:
    void setupUI();
    void createControls();
    void createCircleView();
    void createTableView();
    void createLegend();
    void updateViews();
    void updateLegend();
    QString createFilterString();
    QList<comm_pair_t*> getActivePairsForFilter() const;
    void applySearchFilter(const QString &query);
    void refreshPairListText();
    void updateSearchBarForMode();
    static QString truncateIPv6Address(const QString &address);
    static bool isMACAddress(const QString &address);

    /* UI Components */
    QWidget *m_centralWidget;
    QVBoxLayout *m_mainLayout;
    QHBoxLayout *m_controlsLayout;
    
    /* Control buttons */
    QPushButton *m_top10Btn;
    QPushButton *m_top25Btn;
    QPushButton *m_top50Btn;
    QRadioButton *m_packetsRadio;
    QRadioButton *m_bytesRadio;
    QRadioButton *m_circleRadio;
    QRadioButton *m_tableRadio;
    QRadioButton *m_macRadio;
    QRadioButton *m_ipRadio;
    QPushButton *m_selectAllBtn;
    QPushButton *m_selectNoneBtn;
    QPushButton *m_applyFilterBtn;
    QPushButton *m_clearFilterBtn;
    QPushButton *m_reloadDataBtn;
    QPushButton *m_savePDFBtn;

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

    /* Data */
    analysis_result_t *m_analysisResult;
    GList *m_top_pairs;  /* Track top pairs list to free it properly */
    GList *m_circle_pairs;  /* Limited list for circle widget (exactly top_n pairs) */
    guint m_topN;
    gboolean m_useBytes;
    gboolean m_useMAC;
    QList<comm_pair_t*> m_selectedPairs;
};

#endif /* UI_MAIN_WINDOW_H */
