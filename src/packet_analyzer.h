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

#ifndef PACKET_ANALYZER_H
#define PACKET_ANALYZER_H

#include <glib.h>
#include <epan/epan.h>
#include <epan/packet.h>
#include <epan/tap.h>
#include <epan/to_str.h>
#include <wiretap/wtap.h>

/* Forward declaration - capture_file is defined in UI code */
typedef struct _capture_file capture_file;

#ifdef __cplusplus
extern "C" {
#endif

/* Communication pair structure */
typedef struct _comm_pair {
    gchar *src_addr;      /* Source address (MAC or IP) */
    gchar *dst_addr;      /* Destination address (MAC or IP) */
    gchar *src_mac;       /* Source MAC address (if known) */
    gchar *dst_mac;       /* Destination MAC address (if known) */
    gchar *src_ip;        /* Source IP address (if known) */
    gchar *dst_ip;        /* Destination IP address (if known) */
    gboolean has_tcp;     /* TRUE if TCP observed for this pair */
    gboolean has_udp;     /* TRUE if UDP observed for this pair */
    guint64 packet_count; /* Number of packets */
    guint64 byte_count;   /* Number of bytes */
    gchar *top_protocol;  /* Highest protocol observed */
    gboolean is_mac;      /* TRUE if MAC addresses, FALSE if IP */
    GHashTable *dst_ports; /* Destination port -> packet count (guint16 -> guint64*) */
} comm_pair_t;

/* Protocol statistics */
typedef struct _protocol_stats {
    gchar *protocol_name;
    guint32 color;        /* RGB color value */
    guint64 count;         /* Count for this protocol */
} protocol_stats_t;

/* Analysis result structure */
typedef struct _analysis_result {
    GList *pairs;          /* List of comm_pair_t */
    GHashTable *protocols; /* Hash table of protocol_stats_t */
    guint64 total_packets;
    guint64 total_bytes;
} analysis_result_t;

/* Function prototypes */

/**
 * Initialize packet analyzer
 */
void packet_analyzer_init(void);

/**
 * Cleanup packet analyzer
 */
void packet_analyzer_cleanup(void);

/**
 * Analyze packets from Wireshark capture
 * @param cf Capture file handle (can be NULL for live capture)
 * @param use_mac TRUE to analyze MAC pairs, FALSE for IP pairs
 * @return Analysis result with communication pairs
 */
analysis_result_t* packet_analyzer_analyze(capture_file *cf, gboolean use_mac);

/**
 * Free analysis result
 */
void packet_analyzer_free_result(analysis_result_t *result);

/**
 * Get top N communication pairs
 * @param result Analysis result
 * @param top_n Number of top pairs to return
 * @param use_bytes TRUE to sort by bytes, FALSE by packets
 * @return List of top N pairs
 */
GList* packet_analyzer_get_top_pairs(analysis_result_t *result, guint top_n, gboolean use_bytes);

/**
 * Get protocol color for a protocol name
 * @param protocol_name Name of the protocol
 * @return RGB color value (0xRRGGBB)
 */
guint32 packet_analyzer_get_protocol_color(const gchar *protocol_name);

/**
 * Get all protocols with their colors
 * @return Hash table of protocol_stats_t
 */
GHashTable* packet_analyzer_get_protocols(void);

#ifdef __cplusplus
}
#endif

#endif /* PACKET_ANALYZER_H */
