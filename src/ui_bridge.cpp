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

#include "ui_bridge.h"
#include "ui_main_window.h"
#include "packet_analyzer.h"
#include <QApplication>
#include <QWidget>
#include <QMessageBox>
#include <QDebug>
#include <wsutil/wslog.h>
#include <epan/plugin_if.h>
#include <cfile.h>

#define WS_LOG_DOMAIN "circle_vis"

/* Ensure C++ linkage for this file */
#ifdef __cplusplus
extern "C" {
#endif

/* Forward declaration for plugin_if callback */
void* extract_capture_file(capture_file *cf, void *user_data);

#ifdef __cplusplus
} /* extern "C" */
#endif

/* Global main window instance */
static MainWindow *g_main_window = NULL;

#ifdef __cplusplus
extern "C" {
#endif

void circle_vis_open_window(capture_file *cf)
{
    qDebug() << "circle_vis_open_window: called with cf=" << (void*)cf;
    
    /* Ensure Qt application exists */
    if (!QApplication::instance()) {
        qDebug() << "circle_vis_open_window: No QApplication instance!";
        return;
    }

    /* Create or show main window */
    if (!g_main_window) {
        qDebug() << "circle_vis_open_window: Creating new MainWindow";
        g_main_window = new MainWindow(NULL);
    }

    /* If cf is NULL, try to get it using plugin_if API from C++ side */
    if (!cf) {
        qDebug() << "circle_vis_open_window: cf is NULL, trying plugin_if_get_capture_file";
        cf = (capture_file *)plugin_if_get_capture_file(extract_capture_file, NULL);
        if (cf) {
            qDebug() << "circle_vis_open_window: Got capture_file from plugin_if: state=" << cf->state << "count=" << cf->count;
            ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO, "Got capture_file from plugin_if_get_capture_file in C++: state=%d, count=%u", 
                   cf->state, cf->count);
        } else {
            qDebug() << "circle_vis_open_window: plugin_if_get_capture_file returned NULL";
            ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING, "plugin_if_get_capture_file returned NULL in C++");
        }
    } else {
        qDebug() << "circle_vis_open_window: cf provided, state=" << cf->state << "count=" << cf->count;
    }

    /* Analyze current capture if available */
    /* packet_analyzer_analyze will check if cf is valid */
    if (cf) {
        qDebug() << "circle_vis_open_window: Calling packet_analyzer_analyze";
        /* Use IP by default (FALSE) - MainWindow will handle MAC/IP toggle */
        analysis_result_t *result = packet_analyzer_analyze(cf, FALSE); /* Start with IP */
        if (result) {
            /* Log what we're passing to UI */
            guint pairs_count = result->pairs ? g_list_length(result->pairs) : 0;
            qDebug() << "circle_vis_open_window: Got result with" << pairs_count << "pairs";
            ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO, "Passing %u pairs to UI", pairs_count);
            g_main_window->updateAnalysis(result);
        } else {
            qDebug() << "circle_vis_open_window: packet_analyzer_analyze returned NULL";
            ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING, "packet_analyzer_analyze returned NULL");
        }
    } else {
        qDebug() << "circle_vis_open_window: No capture file available";
        ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING, "No capture file available");
    }

    g_main_window->show();
    g_main_window->raise();
    g_main_window->activateWindow();
}

/* Helper function for plugin_if_get_capture_file callback */
extern "C" void* extract_capture_file(capture_file *cf, void *user_data)
{
    (void)user_data;
    return (void*)cf;
}

void circle_vis_reload_data(void)
{
    qDebug() << "circle_vis_reload_data: called";
    
    /* Ensure Qt application exists */
    if (!QApplication::instance()) {
        qDebug() << "circle_vis_reload_data: No QApplication instance!";
        return;
    }

    /* Ensure main window exists */
    if (!g_main_window) {
        qDebug() << "circle_vis_reload_data: MainWindow doesn't exist, creating it";
        circle_vis_open_window(NULL);
        return;
    }

    /* Get current capture file */
    capture_file *cf = (capture_file *)plugin_if_get_capture_file(extract_capture_file, NULL);
    if (cf) {
        qDebug() << "circle_vis_reload_data: Got capture_file: state=" << cf->state << "count=" << cf->count;
        ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO, "Reloading data: state=%d, count=%u", cf->state, cf->count);
        
        /* Re-analyze with current settings from MainWindow */
        gboolean use_mac = g_main_window->getUseMAC();
        qDebug() << "circle_vis_reload_data: Using MAC=" << use_mac;
        analysis_result_t *result = packet_analyzer_analyze(cf, use_mac);
        if (result) {
            guint pairs_count = result->pairs ? g_list_length(result->pairs) : 0;
            qDebug() << "circle_vis_reload_data: Got result with" << pairs_count << "pairs";
            ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO, "Reloaded data: %u pairs", pairs_count);
            g_main_window->updateAnalysis(result);
        } else {
            qDebug() << "circle_vis_reload_data: packet_analyzer_analyze returned NULL";
            ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING, "packet_analyzer_analyze returned NULL during reload");
        }
    } else {
        qDebug() << "circle_vis_reload_data: No capture file available";
        ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING, "No capture file available for reload");
        QMessageBox::warning(g_main_window, "Reload Data", 
                            "No capture file is currently loaded in Wireshark.\n\nPlease open a PCAP file first.");
    }
}

void circle_vis_update_analysis(analysis_result_t *result)
{
    if (g_main_window && result) {
        g_main_window->updateAnalysis(result);
    }
}

void circle_vis_close_window(void)
{
    if (g_main_window) {
        g_main_window->close();
        delete g_main_window;
        g_main_window = NULL;
    }
}

#ifdef __cplusplus
} /* extern "C" */
#endif
