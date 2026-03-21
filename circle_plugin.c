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

#include "circle_plugin.h"
#include "packet_analyzer.h"
#include "ui_bridge.h"
#include <epan/epan_dissect.h>
#include <epan/proto.h>
#include <epan/tap.h>
#include <epan/capture_dissectors.h>
#include <epan/plugin_if.h>
#include <wsutil/wslog.h>
#include <cfile.h>

#define WS_LOG_DOMAIN "packetcircle"

/* Plugin protocol handle */
int proto_circle_vis = -1;

/* Preferences */
gboolean circle_vis_enabled = TRUE;
gboolean circle_vis_auto_open = TRUE;

/* Main window instance - will be initialized when UI integration is complete */
/* static MainWindow *g_main_window = NULL; */

/* Tap listener data */
typedef struct {
    GHashTable *pairs_table;
    GHashTable *protocols_table;
    gboolean use_mac;
} tap_data_t;

/* Packet tap callback - placeholder for future implementation */
#if 0
static tap_packet_status tap_packet_handler(void *tapdata, packet_info *pinfo, 
                                           epan_dissect_t *edt, const void *data, tap_flags_t flags)
{
    /* TODO: Implement actual packet processing when tap integration is complete */
    (void)tapdata;
    (void)pinfo;
    (void)edt;
    (void)data;
    (void)flags;
    return TAP_PACKET_DONT_REDRAW;
}

/* Analyze capture file - placeholder for future implementation */
static analysis_result_t* analyze_capture_file(capture_file *cf, gboolean use_mac)
{
    (void)cf;
    (void)use_mac;
    
    /* TODO: Implement actual packet analysis when tap integration is complete */
    /* This will use register_tap_listener() to process packets */
    
    return packet_analyzer_analyze(cf, use_mac);
}
#endif

/* Helper function to extract capture_file from plugin_if callback */
static void* extract_capture_file(capture_file *cf, void *user_data G_GNUC_UNUSED)
{
    /* Just return the capture_file pointer */
    return (void*)cf;
}

/* Menu callback to open window */
static void open_circle_window_cb(ext_menubar_gui_type gui_type, void *gui_object, void *user_data)
{
    capture_file *cf = NULL;
    
    (void)gui_type;
    (void)gui_object;
    (void)user_data;
    
    /* Get current capture file from Wireshark using plugin interface */
    /* This may return NULL if no file is loaded - that's OK */
    cf = (capture_file *)plugin_if_get_capture_file(extract_capture_file, NULL);
    
    /* Log what we got - use WARNING level so it's always visible */
    if (cf) {
        ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING, "Got capture_file: state=%d, count=%u", 
               cf->state, cf->count);
    } else {
        ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING, "plugin_if_get_capture_file returned NULL");
    }
    
    /* Open window with capture file (can be NULL if no file is loaded) */
    /* The window will show empty initially if no file is loaded */
    circle_vis_open_window(cf);
}

/* Preference callback */
#if 0
static void prefs_changed_cb(void)
{
    /* Handle preference changes */
}
#endif

/* Menu item handle */
static ext_menu_t *circle_vis_menu = NULL;

/* Plugin registration - called from plugin.c */
void proto_register_circle_vis(void)
{
    int existing_id = proto_get_id_by_short_name("PacketCircle");
    if (existing_id == -1) {
        existing_id = proto_get_id_by_filter_name("packetcircle");
    }
    if (existing_id == -1) {
        existing_id = proto_get_id_by_filter_name("circle_vis");
    }
    if (existing_id != -1) {
        /* Avoid crash if the plugin is loaded twice. */
        ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING,
               "PacketCircle protocol already registered (id=%d); skipping duplicate registration.",
               existing_id);
        proto_circle_vis = existing_id;
        return;
    }

    /* Register protocol */
    proto_circle_vis = proto_register_protocol(
        "PacketCircle (Author: Walter Hofstetter, Repo: https://github.com/netwho/packetcircle)",
        "PacketCircle",
        "packetcircle"
    );

    /* Register UI menu item */
    circle_vis_menu = ext_menubar_register_menu(
        proto_circle_vis,
        "PacketCircle",
        TRUE  /* is_plugin */
    );
    
    /* Set parent menu to Tools */
    ext_menubar_set_parentmenu(circle_vis_menu, "Tools");
    
    /* Add menu entry with callback */
    ext_menubar_add_entry(circle_vis_menu, "Open PacketCircle", 
                         "Open the PacketCircle window",
                         open_circle_window_cb, NULL);

    /* Initialize packet analyzer */
    packet_analyzer_init();
}

void proto_reg_handoff_circle_vis(void)
{
    /* Handoff registration - called after all plugins are loaded */
}

/* Plugin cleanup (called when plugin is unloaded) */
#if 0
static void plugin_cleanup(void)
{
    /* Close UI window */
    circle_vis_close_window();
    
    /* Cleanup packet analyzer */
    packet_analyzer_cleanup();
}
#endif
