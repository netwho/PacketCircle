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

#include "config.h"
#include "packet_analyzer.h"
#include "ui_bridge.h"
#include <string.h>
#include <stdlib.h>
#include <epan/tap.h>
#include <epan/to_str.h>
#include <epan/epan_dissect.h>
#include <epan/frame_data.h>
#include <epan/tvbuff.h>
#include <epan/address.h>
#include <epan/dfilter/dfilter.h>
#include <wiretap/wtap.h>
#include <wsutil/wmem/wmem.h>
#include <wsutil/wmem/wmem_miscutl.h>
#include <wsutil/wmem/wmem_list.h>
#include <wsutil/wslog.h>
#include <epan/plugin_if.h>
#include <cfile.h>

/* Wireshark 4.6+ changed several wiretap/epan APIs:
 * - wtap_rec_init() gained a cap_len parameter
 * - wtap_seek_read() no longer takes a separate Buffer*
 * - epan_dissect_run_with_taps() no longer takes a tvbuff_t*
 * For Wireshark 4.4.x and earlier, we need the old-style calls.
 */
#if VERSION_MINOR < 6
#include <wsutil/buffer.h>
#endif
#ifdef __cplusplus
#include <QApplication>
#endif

#define WS_LOG_DOMAIN "circle_vis"

/* Protocol color mapping */
static GHashTable *protocol_colors = NULL;

/* Initialize protocol color mapping */
static void init_protocol_colors(void)
{
    if (protocol_colors != NULL)
        return;

    protocol_colors = g_hash_table_new(g_str_hash, g_str_equal);

    /* Define protocol colors - Pastel color scheme */
    /* TCP - Pastel Green */
    g_hash_table_insert(protocol_colors, g_strdup("TCP"), GUINT_TO_POINTER(0x90EE90));   /* Light Green */
    /* UDP - Pastel Orange */
    g_hash_table_insert(protocol_colors, g_strdup("UDP"), GUINT_TO_POINTER(0xFFB347));    /* Pastel Orange */
    /* ARP - Pastel Blue */
    g_hash_table_insert(protocol_colors, g_strdup("ARP"), GUINT_TO_POINTER(0x87CEEB));   /* Sky Blue */
    g_hash_table_insert(protocol_colors, g_strdup("RARP"), GUINT_TO_POINTER(0xADD8E6));   /* Light Blue */
    
    /* ICMP - Pastel Cyan */
    g_hash_table_insert(protocol_colors, g_strdup("ICMP"), GUINT_TO_POINTER(0xAFEEEE));   /* Pale Turquoise */
    /* ICMPv6 - Pastel Magenta */
    g_hash_table_insert(protocol_colors, g_strdup("ICMPv6"), GUINT_TO_POINTER(0xFFB6C1));   /* Light Pink */
    /* SCTP - Pastel Yellow */
    g_hash_table_insert(protocol_colors, g_strdup("SCTP"), GUINT_TO_POINTER(0xFFFACD));   /* Lemon Chiffon */
    /* DCCP - Pastel Pink */
    g_hash_table_insert(protocol_colors, g_strdup("DCCP"), GUINT_TO_POINTER(0xFFC0CB));   /* Pink */
    
    /* Routing Protocols - Pastel colors */
    g_hash_table_insert(protocol_colors, g_strdup("OSPF"), GUINT_TO_POINTER(0xFFE4B5));   /* Moccasin */
    g_hash_table_insert(protocol_colors, g_strdup("BGP"), GUINT_TO_POINTER(0xFFB6C1));    /* Light Pink */
    g_hash_table_insert(protocol_colors, g_strdup("RIP"), GUINT_TO_POINTER(0xFFDAB9));    /* Peach Puff */
    g_hash_table_insert(protocol_colors, g_strdup("RIPv2"), GUINT_TO_POINTER(0xFFDAB9));   /* Peach Puff */
    g_hash_table_insert(protocol_colors, g_strdup("EIGRP"), GUINT_TO_POINTER(0xFFE4E1));  /* Misty Rose */
    g_hash_table_insert(protocol_colors, g_strdup("ISIS"), GUINT_TO_POINTER(0xDEB887));   /* Burlywood */
    g_hash_table_insert(protocol_colors, g_strdup("IS-IS"), GUINT_TO_POINTER(0xDEB887));  /* Burlywood */
    g_hash_table_insert(protocol_colors, g_strdup("IGMP"), GUINT_TO_POINTER(0xFFB6C1));  /* Light Pink */
    g_hash_table_insert(protocol_colors, g_strdup("IGMPv2"), GUINT_TO_POINTER(0xFFB6C1)); /* Light Pink */
    g_hash_table_insert(protocol_colors, g_strdup("IGMPv3"), GUINT_TO_POINTER(0xFFB6C1)); /* Light Pink */
    g_hash_table_insert(protocol_colors, g_strdup("PIM"), GUINT_TO_POINTER(0xE6E6FA));   /* Lavender */
    g_hash_table_insert(protocol_colors, g_strdup("VRRP"), GUINT_TO_POINTER(0xF0E68C));  /* Khaki */
    g_hash_table_insert(protocol_colors, g_strdup("HSRP"), GUINT_TO_POINTER(0xDDA0DD));   /* Plum */
    
    /* Layer 3 protocols - Pastel Gray */
    g_hash_table_insert(protocol_colors, g_strdup("IP"), GUINT_TO_POINTER(0xD3D3D3));     /* Light Gray */
    g_hash_table_insert(protocol_colors, g_strdup("IPv4"), GUINT_TO_POINTER(0xD3D3D3));    /* Light Gray */
    g_hash_table_insert(protocol_colors, g_strdup("IPv6"), GUINT_TO_POINTER(0xE0E0E0));   /* Gainsboro */
    
    /* Layer 2 protocols */
    g_hash_table_insert(protocol_colors, g_strdup("Ethernet"), GUINT_TO_POINTER(0xC0C0C0)); /* Silver */
    
    /* Fallback */
    g_hash_table_insert(protocol_colors, g_strdup("Unknown"), GUINT_TO_POINTER(0x808080)); /* Gray */
}

/* Compare functions removed - now using inline comparison in packet_analyzer_get_top_pairs */

/* Free per-port stats entry */
static void free_port_stats(gpointer data)
{
    g_free(data);
}

static void free_comm_pair(gpointer data)
{
    comm_pair_t *pair = (comm_pair_t *)data;
    if (pair) {
        g_free(pair->src_addr);
        g_free(pair->dst_addr);
        g_free(pair->resolved_src);
        g_free(pair->resolved_dst);
        g_free(pair->src_mac);
        g_free(pair->dst_mac);
        g_free(pair->src_ip);
        g_free(pair->dst_ip);
        g_free(pair->top_protocol);
        if (pair->dst_ports) {
            g_hash_table_destroy(pair->dst_ports);
        }
        /* Wi-Fi fields */
        g_free(pair->wifi_bssid);
        g_free(pair->wifi_ssid);
        g_free(pair);
    }
}

/* Free protocol stats */
static void free_protocol_stats(gpointer data)
{
    protocol_stats_t *stats = (protocol_stats_t *)data;
    if (!stats)
        return;
    
    /* protocol_name might be NULL, g_free handles NULL safely */
    g_free(stats->protocol_name);
    g_free(stats);
}

/* Copy protocols hash table - creates a deep copy */
static GHashTable* copy_protocols_table(GHashTable *source)
{
    GHashTable *copy;
    GHashTableIter iter;
    gpointer key, value;
    
    if (!source)
        return g_hash_table_new_full(g_str_hash, g_str_equal, g_free, free_protocol_stats);
    
    copy = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, free_protocol_stats);
    
    g_hash_table_iter_init(&iter, source);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        protocol_stats_t *src_stats = (protocol_stats_t *)value;
        if (!src_stats)
            continue;
            
        protocol_stats_t *dst_stats = g_new0(protocol_stats_t, 1);
        /* Always ensure protocol_name is set - never NULL */
        if (src_stats->protocol_name && *src_stats->protocol_name) {
            dst_stats->protocol_name = g_strdup(src_stats->protocol_name);
        } else {
            dst_stats->protocol_name = g_strdup("Unknown");
        }
        dst_stats->color = src_stats->color;
        dst_stats->count = src_stats->count;
        
        if (key && *((gchar *)key)) {
            g_hash_table_insert(copy, g_strdup((gchar *)key), dst_stats);
        } else {
            /* If key is NULL or empty, free the stats we just allocated */
            g_free(dst_stats->protocol_name);
            g_free(dst_stats);
        }
    }
    
    return copy;
}

/* Get or create communication pair */
static comm_pair_t* get_or_create_pair(GHashTable *pairs_table, const gchar *src, const gchar *dst, gboolean is_mac)
{
    gchar *key = g_strdup_printf("%s->%s", src, dst);
    comm_pair_t *pair = (comm_pair_t *)g_hash_table_lookup(pairs_table, key);

    if (!pair) {
        pair = g_new0(comm_pair_t, 1);
        pair->src_addr = g_strdup(src);
        pair->dst_addr = g_strdup(dst);
        pair->resolved_src = NULL;  /* Will be set from address_to_display() */
        pair->resolved_dst = NULL;  /* Will be set from address_to_display() */
        pair->src_mac = NULL;
        pair->dst_mac = NULL;
        pair->src_ip = NULL;
        pair->dst_ip = NULL;
        pair->has_tcp = FALSE;
        pair->has_udp = FALSE;
        pair->is_mac = is_mac;
        pair->packet_count = 0;
        pair->byte_count = 0;
        pair->top_protocol = NULL;  /* Will be set when first packet is processed */
        pair->dst_ports = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, free_port_stats);
        g_hash_table_insert(pairs_table, key, pair);
    } else {
        g_free(key);
    }

    return pair;
}

/* Update protocol statistics - TODO: implement when needed */
#if 0
static void update_protocol_stats(GHashTable *protocols_table, const gchar *protocol_name, guint64 bytes)
{
    protocol_stats_t *stats = (protocol_stats_t *)g_hash_table_lookup(protocols_table, protocol_name);

    if (!stats) {
        stats = g_new0(protocol_stats_t, 1);
        stats->protocol_name = g_strdup(protocol_name);
        stats->color = packet_analyzer_get_protocol_color(protocol_name);
        stats->count = 0;
        g_hash_table_insert(protocols_table, g_strdup(protocol_name), stats);
    }

    stats->count += bytes;
}
#endif

/* Tap data structure for packet processing */
typedef struct {
    GHashTable *pairs_table;
    GHashTable *protocols_table;
    gboolean use_mac;
    AnalysisMode mode;          /* Current analysis mode */
} tap_data_t;

/* Packet tap callback - processes each packet */
static tap_packet_status circle_vis_tap_packet_cb(void *tapdata, packet_info *pinfo, epan_dissect_t *edt, const void *data, tap_flags_t flags)
{
    tap_data_t *tap_data = (tap_data_t *)tapdata;
    comm_pair_t *pair;
    const gchar *src_addr = NULL;
    const gchar *dst_addr = NULL;
    gchar *protocol_name = NULL;
    guint32 packet_len;
    static guint32 callback_count = 0;

    (void)edt;
    (void)data;
    (void)flags;

    if (!tap_data || !pinfo) {
        ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING, "Tap callback: NULL tap_data or pinfo");
        return TAP_PACKET_DONT_REDRAW;
    }
    
    callback_count++;
    if (callback_count <= 10 || callback_count % 1000 == 0) {
        ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING, "Tap callback called %u times", callback_count);
    }
    
    /* Log current_proto immediately to see what we're getting */
    if (callback_count <= 20) {
        if (pinfo->current_proto) {
            ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING, "Packet %u: pinfo->current_proto = '%s' (ptr=%p)", 
                   callback_count, pinfo->current_proto, pinfo->current_proto);
        } else {
            ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING, "Packet %u: pinfo->current_proto is NULL", callback_count);
        }
    }

    /* Log before accessing pinfo->fd to see if that's where we crash */
    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING, "Packet %u: About to check pinfo->fd", callback_count);

    /* Check if frame_data is available - do this early */
    /* Access pinfo->fd carefully - it might be causing the crash */
    if (!pinfo || !pinfo->fd) {
        ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING, "Packet %u: pinfo=%p, pinfo->fd=%p", callback_count, pinfo, pinfo ? pinfo->fd : NULL);
        return TAP_PACKET_DONT_REDRAW;
    }
    
    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING, "Packet %u: pinfo->fd is valid", callback_count);

    /* Check if pinfo->pool is valid */
    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING, "Packet %u: About to check pinfo->pool", callback_count);
    if (!pinfo->pool) {
        ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING, "Packet %u: pinfo->pool is NULL", callback_count);
        return TAP_PACKET_DONT_REDRAW;
    }
    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING, "Packet %u: pinfo->pool is valid", callback_count);

    /* Get protocol name from packet info */
    /* CRITICAL: Check application-layer protocols FIRST before transport-layer (UDP/TCP) */
    /* This ensures OSPF (over UDP) is detected as OSPF, not UDP */
    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING, "Packet %u: About to get protocol name", callback_count);
    protocol_name = NULL;
    
    /* Log ptype and ports for debugging - always log first 20 packets */
    if (callback_count <= 20) {
        ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING, "Packet %u: ptype=%d, srcport=%u, destport=%u, src.type=%d, current_proto=%s", 
               callback_count, pinfo->ptype, pinfo->srcport, pinfo->destport, pinfo->src.type,
               pinfo->current_proto ? pinfo->current_proto : "NULL");
    }
    
    /* PRIORITY 1: Check current_proto for application-layer protocols FIRST */
    /* This must happen BEFORE checking ptype, because OSPF/BGP/etc run over UDP/TCP */
    /* Skip if current_proto is "<Missing Protocol Name>" */
    if (pinfo->current_proto && *(pinfo->current_proto) && 
        g_strcmp0(pinfo->current_proto, "<Missing Protocol Name>") != 0 &&
        g_strstr_len(pinfo->current_proto, -1, "Missing") == NULL) {
        const gchar *cp = pinfo->current_proto;
        
        /* Check for ARP/RARP first (Layer 2) */
        if (g_strcmp0(cp, "ARP") == 0 || g_strcmp0(cp, "RARP") == 0) {
            protocol_name = g_strdup(cp);
            ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING, "Packet %u: ✓ Detected %s from current_proto", 
                   callback_count, protocol_name);
        }
        /* Check for routing/infrastructure protocols (application-layer over UDP/TCP) */
        else if (g_strcmp0(cp, "OSPF") == 0 || g_strcmp0(cp, "BGP") == 0 ||
                 g_strcmp0(cp, "RIP") == 0 || g_strcmp0(cp, "RIPv2") == 0 ||
                 g_strcmp0(cp, "EIGRP") == 0 || g_strcmp0(cp, "ISIS") == 0 ||
                 g_strcmp0(cp, "IS-IS") == 0 || g_strcmp0(cp, "IGMP") == 0 ||
                 g_strcmp0(cp, "IGMPv2") == 0 || g_strcmp0(cp, "IGMPv3") == 0 ||
                 g_strcmp0(cp, "PIM") == 0 || g_strcmp0(cp, "VRRP") == 0 ||
                 g_strcmp0(cp, "HSRP") == 0) {
            protocol_name = g_strdup(cp);
            ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING, "Packet %u: ✓ Detected Infrastructure protocol: %s (over UDP/TCP)", 
                   callback_count, protocol_name);
        }
        /* Check for ICMP variants */
        else if (g_strcmp0(cp, "ICMP") == 0 || g_strcmp0(cp, "ICMPv6") == 0) {
            protocol_name = g_strdup(cp);
            ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING, "Packet %u: ✓ Detected %s from current_proto", 
                   callback_count, protocol_name);
        }
    }
    
    /* PRIORITY 1.5: Check for routing protocols by port (when current_proto is missing) */
    /* This is a fallback when current_proto doesn't work */
    if (!protocol_name && (pinfo->srcport != 0 || pinfo->destport != 0)) {
        guint16 port = (pinfo->srcport != 0) ? pinfo->srcport : pinfo->destport;
        
        /* OSPF uses port 89 */
        if (port == 89) {
            protocol_name = g_strdup("OSPF");
            ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING, "Packet %u: ✓ Detected OSPF from port 89", callback_count);
        }
        /* BGP uses port 179 */
        else if (port == 179) {
            protocol_name = g_strdup("BGP");
            ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING, "Packet %u: ✓ Detected BGP from port 179", callback_count);
        }
        /* RIP uses port 520 */
        else if (port == 520) {
            protocol_name = g_strdup("RIP");
            ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING, "Packet %u: ✓ Detected RIP from port 520", callback_count);
        }
    }
    
    /* PRIORITY 2: Check for ARP using address types (if current_proto didn't catch it) */
    if (!protocol_name && pinfo->src.type == AT_ETHER && pinfo->dst.type == AT_ETHER) {
        /* ARP has Ethernet addresses but no ports */
        if (pinfo->srcport == 0 && pinfo->destport == 0) {
            /* Check current_proto more broadly for ARP */
            if (pinfo->current_proto && *(pinfo->current_proto)) {
                const gchar *cp = pinfo->current_proto;
                if (g_strstr_len(cp, -1, "ARP") != NULL) {
                    protocol_name = g_strdup("ARP");
                    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING, "Packet %u: ✓ Inferred ARP from Ethernet addresses and current_proto: %s", 
                           callback_count, cp);
                }
            }
        }
    }
    
    /* PRIORITY 3.5: IP packets with no ports — could be IGMP, IP fragments,
     * GRE, ESP, etc.  ICMP is already caught above via pinfo->current_proto
     * in PRIORITY 1.  For IGMP, lightweight dissection (TL_REQUIRES_NOTHING)
     * may not run the IGMP dissector, so current_proto stays "IPv4" and the
     * packet misses PRIORITY 1.  Detect IGMP by checking for IPv4 multicast
     * destinations (224.0.0.0/4) with no transport layer.                    */
    if (!protocol_name && pinfo->ptype == PT_NONE &&
        pinfo->srcport == 0 && pinfo->destport == 0 &&
        (pinfo->src.type == AT_IPv4 || pinfo->dst.type == AT_IPv4)) {
        /* Check if destination is IPv4 multicast (224.0.0.0/4) */
        if (pinfo->dst.type == AT_IPv4 && pinfo->dst.len == 4) {
            const guint8 *dst_bytes = (const guint8 *)pinfo->dst.data;
            if (dst_bytes && (dst_bytes[0] >= 224 && dst_bytes[0] <= 239)) {
                protocol_name = g_strdup("IGMP");
                if (callback_count <= 20) {
                    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING,
                           "Packet %u: ✓ Detected IGMP from IPv4 multicast dst %u.%u.%u.%u",
                           callback_count, dst_bytes[0], dst_bytes[1], dst_bytes[2], dst_bytes[3]);
                }
            }
        }
    }
    
    /* PRIORITY 3: Check packet type (ptype) - for transport-layer protocols */
    /* Only use this if no application-layer protocol was found */
    if (!protocol_name) {
        if (pinfo->ptype == PT_TCP) {
            protocol_name = g_strdup("TCP");
            if (callback_count <= 10) {
                ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING, "Packet %u: Detected TCP from ptype (ports: %u->%u)", 
                       callback_count, pinfo->srcport, pinfo->destport);
            }
        } else if (pinfo->ptype == PT_UDP) {
            protocol_name = g_strdup("UDP");
            if (callback_count <= 10) {
                ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING, "Packet %u: Detected UDP from ptype (ports: %u->%u)", 
                       callback_count, pinfo->srcport, pinfo->destport);
            }
        } else if (pinfo->ptype == PT_SCTP) {
            protocol_name = g_strdup("SCTP");
            if (callback_count <= 10) {
                ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING, "Packet %u: Detected SCTP from ptype (ports: %u->%u)", 
                       callback_count, pinfo->srcport, pinfo->destport);
            }
        } else if (pinfo->ptype == PT_DCCP) {
            protocol_name = g_strdup("DCCP");
            if (callback_count <= 10) {
                ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING, "Packet %u: Detected DCCP from ptype (ports: %u->%u)", 
                       callback_count, pinfo->srcport, pinfo->destport);
            }
        }
        /* If we have ports but ptype is not set or unknown, do NOT blindly
         * infer TCP.  This catches IP fragments where the first fragment
         * carries a UDP header (ports populated) but ptype might not be set
         * correctly by lightweight dissection.  Let it fall through to the
         * generic "IP" fallback instead.                                     */
        else if (!protocol_name && (pinfo->srcport != 0 || pinfo->destport != 0)) {
            if (callback_count <= 10) {
                ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING, "Packet %u: Has ports but unknown ptype=%u (ports: %u->%u) - NOT assuming TCP", 
                       callback_count, pinfo->ptype, pinfo->srcport, pinfo->destport);
            }
            /* Leave protocol_name NULL — generic fallback will classify as "IP" */
        }
    }
    
    /* Fallback: use a generic name based on address type */
    if (!protocol_name) {
        if (pinfo->src.type == AT_IPv4 || pinfo->src.type == AT_IPv6) {
            protocol_name = g_strdup("IP");
        } else if (pinfo->src.type == AT_ETHER) {
            protocol_name = g_strdup("Ethernet");
        } else {
            protocol_name = g_strdup("Unknown");
        }
        if (callback_count <= 10) {
            ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING, "Packet %u: Using fallback protocol: %s (src.type=%d)", 
                   callback_count, protocol_name, pinfo->src.type);
        }
    }
    
    /* Ensure we have a valid protocol name */
    if (!protocol_name || !*protocol_name) {
        if (protocol_name) {
            g_free(protocol_name);
        }
        protocol_name = g_strdup("Unknown");
    }

    /* Get addresses based on MAC or IP preference */
    /* Log address types for debugging - be very careful accessing pinfo fields */
    if (callback_count <= 10) {
        ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING, "Packet %u: About to check addresses, use_mac=%d", 
               callback_count, tap_data->use_mac);
    }
    
    /* Extract both MAC and IP where possible to build mappings */
    const gchar *mac_src = NULL;
    const gchar *mac_dst = NULL;
    const gchar *ip_src = NULL;
    const gchar *ip_dst = NULL;

    if (pinfo->dl_src.type == AT_ETHER && pinfo->dl_dst.type == AT_ETHER) {
        mac_src = address_to_str(wmem_epan_scope(), &(pinfo->dl_src));
        mac_dst = address_to_str(wmem_epan_scope(), &(pinfo->dl_dst));
    }

    if ((pinfo->net_src.type == AT_IPv4 || pinfo->net_src.type == AT_IPv6) &&
        (pinfo->net_dst.type == AT_IPv4 || pinfo->net_dst.type == AT_IPv6)) {
        ip_src = address_to_str(wmem_epan_scope(), &(pinfo->net_src));
        ip_dst = address_to_str(wmem_epan_scope(), &(pinfo->net_dst));
    }

    /* Safely check address types - wrap in try-catch equivalent by checking validity first */
    /* Check if we have valid addresses before trying to extract them */
    if (tap_data->use_mac) {
        /* Check MAC addresses */
        if (mac_src && mac_dst) {
            if (callback_count <= 10) {
                ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING, "Packet %u: Extracting MAC addresses", callback_count);
            }
            src_addr = mac_src;
            dst_addr = mac_dst;
        } else {
            /* Address type doesn't match - skip this packet */
            if (callback_count <= 20) {
                ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING, "Skipping packet %u: MAC address type mismatch (src.type=%d, dst.type=%d)", 
                       callback_count, pinfo->dl_src.type, pinfo->dl_dst.type);
            }
            g_free(protocol_name);
            return TAP_PACKET_DONT_REDRAW;
        }
    } else {
        /* Looking for IP addresses - check both src and dst are IP */
        if (callback_count <= 10) {
            ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING, "Packet %u: Checking IP addresses (src.type=%d, dst.type=%d)", 
                   callback_count, pinfo->net_src.type, pinfo->net_dst.type);
        }
        if (ip_src && ip_dst) {
            if (callback_count <= 10) {
                ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING, "Packet %u: Extracting IP addresses", callback_count);
            }
            src_addr = ip_src;
            dst_addr = ip_dst;
        } else {
            /* Address type doesn't match - skip this packet */
            if (callback_count <= 20) {
                ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING, "Skipping packet %u: IP address type mismatch (src.type=%d, dst.type=%d)", 
                       callback_count, pinfo->net_src.type, pinfo->net_dst.type);
            }
            g_free(protocol_name);
            return TAP_PACKET_DONT_REDRAW;
        }
    }

    if (!src_addr || !dst_addr) {
        ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING, "Packet %u: address_to_str returned NULL (src=%p, dst=%p)", 
               callback_count, src_addr, dst_addr);
        g_free(protocol_name);
        return TAP_PACKET_DONT_REDRAW;
    }
    
    if (callback_count <= 10) {
        ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING, "Packet %u: src=%s, dst=%s", callback_count, src_addr, dst_addr);
    }

    /* Get or create pair - addresses from pinfo->pool are valid for the lifetime of the packet */
    /* We need to copy them since we're storing them in our hash table */
    if (!src_addr || !dst_addr) {
        ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING, "Packet %u: NULL addresses before get_or_create_pair", callback_count);
        g_free(protocol_name);
        return TAP_PACKET_DONT_REDRAW;
    }
    
    pair = get_or_create_pair(tap_data->pairs_table, src_addr, dst_addr, tap_data->use_mac);
    
    if (!pair) {
        ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING, "Packet %u: get_or_create_pair returned NULL", callback_count);
        g_free(protocol_name);
        return TAP_PACKET_DONT_REDRAW;
    }

    if (g_strcmp0(protocol_name, "TCP") == 0) {
        pair->has_tcp = TRUE;
    } else if (g_strcmp0(protocol_name, "UDP") == 0) {
        pair->has_udp = TRUE;
    }

    /* Track destination port for this pair — ONLY for TCP / UDP packets so
     * that higher-layer protocols (OSPF, ICMP, …) don't pollute the port
     * statistics with misleading port numbers. */
    if (pinfo->destport != 0 && pair->dst_ports &&
        (pinfo->ptype == PT_TCP || pinfo->ptype == PT_UDP)) {
        gpointer port_key = GUINT_TO_POINTER((guint)pinfo->destport);
        port_stats_t *ps = (port_stats_t *)g_hash_table_lookup(pair->dst_ports, port_key);
        if (ps) {
            ps->count++;
        } else {
            ps = g_new0(port_stats_t, 1);
            ps->count = 1;
            g_hash_table_insert(pair->dst_ports, port_key, ps);
        }
        /* Record which transport protocol(s) use this specific port */
        if (pinfo->ptype == PT_TCP) ps->is_tcp = TRUE;
        if (pinfo->ptype == PT_UDP) ps->is_udp = TRUE;
    }

    /* Populate MAC/IP mappings when available */
    if (mac_src && !pair->src_mac) {
        pair->src_mac = g_strdup(mac_src);
    }
    if (mac_dst && !pair->dst_mac) {
        pair->dst_mac = g_strdup(mac_dst);
    }
    if (ip_src && !pair->src_ip) {
        pair->src_ip = g_strdup(ip_src);
    }
    if (ip_dst && !pair->dst_ip) {
        pair->dst_ip = g_strdup(ip_dst);
    }

    /* Populate resolved display names using Wireshark's name resolution settings.
     * address_to_display() returns hostnames when resolution is ON, raw addresses when OFF.
     * We only set these once per pair (first packet). */
    if (!pair->resolved_src) {
        if (tap_data->use_mac) {
            const gchar *resolved = address_to_display(wmem_epan_scope(), &(pinfo->dl_src));
            pair->resolved_src = g_strdup(resolved ? resolved : src_addr);
        } else {
            const gchar *resolved = address_to_display(wmem_epan_scope(), &(pinfo->net_src));
            pair->resolved_src = g_strdup(resolved ? resolved : src_addr);
        }
    }
    if (!pair->resolved_dst) {
        if (tap_data->use_mac) {
            const gchar *resolved = address_to_display(wmem_epan_scope(), &(pinfo->dl_dst));
            pair->resolved_dst = g_strdup(resolved ? resolved : dst_addr);
        } else {
            const gchar *resolved = address_to_display(wmem_epan_scope(), &(pinfo->net_dst));
            pair->resolved_dst = g_strdup(resolved ? resolved : dst_addr);
        }
    }
    
    if (callback_count <= 5) {
        ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING, "Packet %u: pair created/found, count=%" G_GUINT64_FORMAT, 
               callback_count, pair->packet_count);
    }

    /* Update statistics */
    pair->packet_count++;
    
    /* Safely get packet length */
    if (pinfo->fd) {
        packet_len = pinfo->fd->pkt_len;
        if (packet_len > 0) {
            pair->byte_count += packet_len;
        }
    } else {
        ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING, "Packet %u: pinfo->fd is NULL", callback_count);
        packet_len = 0;
    }

    /* Update top protocol - focus on Layer 4 protocols (TCP, UDP, ICMP, etc.) */
    /* CRITICAL: Always ensure pair->top_protocol is set to a valid non-NULL string */
    
    /* Validate protocol_name - ensure it's never NULL or empty */
    /* Also check for Qt's "<Missing Protocol Name>" placeholder string */
    if (!protocol_name || !*protocol_name || 
        g_strcmp0(protocol_name, "<Missing Protocol Name>") == 0 ||
        g_strstr_len(protocol_name, -1, "Missing") != NULL) {
        ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING, "Packet %u: protocol_name is NULL/empty/invalid ('%s'), using 'Unknown'", 
               callback_count, protocol_name ? protocol_name : "NULL");
        if (protocol_name) {
            g_free(protocol_name);
        }
        protocol_name = g_strdup("Unknown");
    }
    
    /* Layer 4 protocols (preferred) */
    gboolean is_layer4 = (g_strcmp0(protocol_name, "TCP") == 0 || 
                         g_strcmp0(protocol_name, "UDP") == 0 ||
                         g_strcmp0(protocol_name, "ICMP") == 0 ||
                         g_strcmp0(protocol_name, "ICMPv6") == 0 ||
                         g_strcmp0(protocol_name, "SCTP") == 0 ||
                         g_strcmp0(protocol_name, "DCCP") == 0);
    
    /* Layer 3 protocols */
    gboolean is_layer3 = (g_strcmp0(protocol_name, "IP") == 0 ||
                         g_strcmp0(protocol_name, "IPv4") == 0 ||
                         g_strcmp0(protocol_name, "IPv6") == 0);
    
    /* Layer 2 protocols */
    gboolean is_layer2 = (g_strcmp0(protocol_name, "ARP") == 0 ||
                         g_strcmp0(protocol_name, "Ethernet") == 0);
    
    gboolean should_update = FALSE;
    
    if (!pair->top_protocol || !*pair->top_protocol) {
        /* First protocol for this pair or it's NULL/empty - always set it */
        should_update = TRUE;
        if (callback_count <= 10) {
            ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING, "Packet %u: Setting initial protocol: %s", 
                   callback_count, protocol_name);
        }
    } else if (is_layer4) {
        /* Layer 4 protocol - always prefer it over Layer 3/2 */
        should_update = TRUE;
        if (callback_count <= 10) {
            ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING, "Packet %u: Updating to Layer 4 protocol: %s (was: %s)", 
                   callback_count, protocol_name, pair->top_protocol);
        }
    } else if (is_layer3 && (g_strcmp0(pair->top_protocol, "Ethernet") == 0 || 
                              g_strcmp0(pair->top_protocol, "Unknown") == 0)) {
        /* Layer 3 protocol - prefer it over Layer 2 or Unknown */
        should_update = TRUE;
        if (callback_count <= 10) {
            ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING, "Packet %u: Updating to Layer 3 protocol: %s", 
                   callback_count, protocol_name);
        }
    } else if (is_layer2 && g_strcmp0(pair->top_protocol, "Unknown") == 0) {
        /* Layer 2 protocol - prefer it over Unknown */
        should_update = TRUE;
        if (callback_count <= 10) {
            ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING, "Packet %u: Updating to Layer 2 protocol: %s", 
                   callback_count, protocol_name);
        }
    }
    
    /* Always ensure top_protocol is set */
    if (should_update || !pair->top_protocol) {
        /* Final validation before storing - never store invalid strings */
        if (!protocol_name || !*protocol_name || 
            g_strcmp0(protocol_name, "<Missing Protocol Name>") == 0 ||
            g_strstr_len(protocol_name, -1, "Missing") != NULL) {
            ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING, "Packet %u: Invalid protocol_name before storing, using 'Unknown'", callback_count);
            if (protocol_name && protocol_name != g_strdup("Unknown")) {
                g_free(protocol_name);
            }
            protocol_name = g_strdup("Unknown");
        }
        
        if (pair->top_protocol) {
            g_free(pair->top_protocol);
        }
        pair->top_protocol = g_strdup(protocol_name);
        if (callback_count <= 10) {
            ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING, "Packet %u: Set pair top_protocol to: '%s'", 
                   callback_count, pair->top_protocol);
        }
    }
    
    /* Final safety check - should never be NULL or contain "Missing" at this point */
    if (!pair->top_protocol || !*pair->top_protocol ||
        g_strcmp0(pair->top_protocol, "<Missing Protocol Name>") == 0 ||
        g_strstr_len(pair->top_protocol, -1, "Missing") != NULL) {
        ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING, "Packet %u: ERROR - top_protocol is invalid ('%s'), fixing to 'Unknown'!", 
               callback_count, pair->top_protocol ? pair->top_protocol : "NULL");
        if (pair->top_protocol) {
            g_free(pair->top_protocol);
        }
        pair->top_protocol = g_strdup("Unknown");
    }

    /* Update protocol statistics */
    protocol_stats_t *stats = (protocol_stats_t *)g_hash_table_lookup(tap_data->protocols_table, protocol_name);
    if (!stats) {
        stats = g_new0(protocol_stats_t, 1);
        stats->protocol_name = g_strdup(protocol_name);
        stats->color = packet_analyzer_get_protocol_color(protocol_name);
        stats->count = 0;
        g_hash_table_insert(tap_data->protocols_table, g_strdup(protocol_name), stats);
    }
    if (packet_len > 0) {
        stats->count += packet_len;
    }

    g_free(protocol_name);
    return TAP_PACKET_DONT_REDRAW;
}

/* ------------------------------------------------------------------ */
/* Wi-Fi Monitor Mode Detection                                        */
/* ------------------------------------------------------------------ */

/* Quick recursive check for Wi-Fi-related protocol tree nodes */
static gboolean tree_contains_wifi(proto_node *node, int depth)
{
    if (!node || depth > 40) return FALSE;
    field_info *fi = node->finfo;
    if (fi && fi->hfinfo && fi->hfinfo->abbrev) {
        const gchar *abbrev = fi->hfinfo->abbrev;
        if (g_str_has_prefix(abbrev, "wlan.") ||
            g_str_has_prefix(abbrev, "radiotap.") ||
            g_str_has_prefix(abbrev, "wlan_radio.")) {
            return TRUE;
        }
    }
    for (proto_node *child = node->first_child; child; child = child->next) {
        if (tree_contains_wifi(child, depth + 1))
            return TRUE;
    }
    return FALSE;
}

/* Detect whether the capture file is a Wi-Fi monitor capture.
 * Strategy:
 * 1) Check file-level encapsulation from wiretap (fast path).
 * 2) If encapsulation is inconclusive (e.g., PER_PACKET), pre‑scan the first
 *    few frames with a proto tree and look for wlan/radiotap fields. */
static gboolean detect_wifi_monitor_capture(capture_file *cf)
{
    if (!cf || !cf->provider.wth)
        return FALSE;

    int encap = wtap_file_encap(cf->provider.wth);
    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO,
           "detect_wifi_monitor_capture: encap=%d", encap);

    switch (encap) {
    case WTAP_ENCAP_IEEE_802_11_RADIOTAP:   /* 127 */
    case WTAP_ENCAP_IEEE_802_11:            /*   6 - bare 802.11 */
    case WTAP_ENCAP_IEEE_802_11_PRISM:      /* 119 */
    case WTAP_ENCAP_IEEE_802_11_WITH_RADIO: /* 116 */
    case WTAP_ENCAP_PPI:                    /* 192 */
        ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO,
               "Detected Wi-Fi monitor capture (encap=%d)", encap);
        return TRUE;
    default:
        break; /* Fall through to pre-scan */
    }

    /* Pre‑scan: handle WTAP_ENCAP_PER_PACKET or other ambiguous types */
    if (cf->state == FILE_READ_DONE && cf->provider.frames && cf->count > 0) {
        epan_dissect_t *edt = epan_dissect_new(cf->epan, TRUE, TRUE);
        const guint32 MAX_PROBE = (cf->count < 200) ? cf->count : 200;  /* cap pre-scan */
        for (guint32 framenum = 1; framenum <= MAX_PROBE; framenum++) {
            frame_data *fdata = frame_data_sequence_find(cf->provider.frames, framenum);
            if (!fdata || fdata->file_off < 0)
                continue;
            int err = 0; gchar *err_info = NULL; wtap_rec rec; gboolean ok;
#if VERSION_MINOR >= 6
            wtap_rec_init(&rec, fdata->cap_len);
            ok = wtap_seek_read(cf->provider.wth, fdata->file_off, &rec, &err, &err_info);
            if (ok) {
                int fts = wtap_file_type_subtype(cf->provider.wth);
                epan_dissect_run(edt, fts, &rec, fdata, NULL);
#else
            Buffer buf; ws_buffer_init(&buf, fdata->cap_len);
            wtap_rec_init(&rec);
            ok = wtap_seek_read(cf->provider.wth, fdata->file_off, &rec, &buf, &err, &err_info);
            if (ok) {
                int fts = wtap_file_type_subtype(cf->provider.wth);
                tvbuff_t *tvb = tvb_new_real_data(ws_buffer_start_ptr(&buf),
                                                  rec.rec_header.packet_header.caplen,
                                                  rec.rec_header.packet_header.len);
                epan_dissect_run(edt, fts, &rec, tvb, fdata, NULL);
#endif
                if (edt->tree && tree_contains_wifi(edt->tree, 0)) {
                    epan_dissect_free(edt);
#if VERSION_MINOR >= 6
                    wtap_rec_cleanup(&rec);
#else
                    wtap_rec_cleanup(&rec);
                    ws_buffer_free(&buf);
#endif
                    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO,
                           "Pre-scan detected Wi-Fi fields in first %u frames", framenum);
                    return TRUE;
                }
                epan_dissect_reset(edt);
            }
#if VERSION_MINOR >= 6
            wtap_rec_cleanup(&rec);
#else
            wtap_rec_cleanup(&rec);
            ws_buffer_free(&buf);
#endif
            if (err_info) { g_free(err_info); err_info = NULL; }
        }
        epan_dissect_free(edt);
    }

    return FALSE;
}

/* Forward declarations for helpers defined later (TLS section) but
 * also used by the Wi-Fi proto-tree walker below.                    */
static void   fill_label_compat(field_info *fi, gchar *buf);
static gchar* label_value(const gchar *label);

/* ------------------------------------------------------------------ */
/* Wi-Fi Proto-Tree Walker                                             */
/* ------------------------------------------------------------------ */

/* Context for walking the proto tree of a single Wi-Fi frame */
typedef struct {
    gchar   *bssid;     /* wlan.bssid */
    gchar   *ta;        /* wlan.ta (transmitter address) */
    gchar   *ra;        /* wlan.ra (receiver address) */
    gchar   *sa;        /* wlan.sa (source address) */
    gchar   *da;        /* wlan.da (destination address) */
    gchar   *ssid;      /* wlan.ssid / wlan_mgt.ssid */
    gint16   rssi;      /* radiotap.dbm_antsignal (or wlan_radio.signal_dbm) */
    gboolean rssi_found;
    guint16  channel;   /* radiotap.channel.freq converted, or wlan_radio.channel */
    guint8   fc_type;   /* wlan.fc.type */
    guint8   fc_subtype;/* wlan.fc.type_subtype */
    gboolean retry;     /* wlan.fc.retry */
    gboolean has_type;
    guint16  reason_code;   /* wlan.fixed.reason_code (deauth/disassoc) */
    gboolean reason_found;
    guint8   phy;           /* wlan_radio.phy */
    gboolean phy_found;
} wifi_frame_ctx_t;

static void walk_wifi_proto_tree(proto_node *node, wifi_frame_ctx_t *ctx, int depth)
{
    if (!node || depth > 40) return;

    field_info *fi = node->finfo;
    if (fi && fi->hfinfo && fi->hfinfo->abbrev) {
        const gchar *abbrev = fi->hfinfo->abbrev;
        gchar label[ITEM_LABEL_LENGTH];
        label[0] = '\0';

        /* BSSID */
        if (g_strcmp0(abbrev, "wlan.bssid") == 0 && !ctx->bssid) {
            fill_label_compat(fi, label);
            ctx->bssid = label_value(label);
        }
        /* TA */
        if (g_strcmp0(abbrev, "wlan.ta") == 0 && !ctx->ta) {
            fill_label_compat(fi, label);
            ctx->ta = label_value(label);
        }
        /* RA */
        if (g_strcmp0(abbrev, "wlan.ra") == 0 && !ctx->ra) {
            fill_label_compat(fi, label);
            ctx->ra = label_value(label);
        }
        /* SA */
        if (g_strcmp0(abbrev, "wlan.sa") == 0 && !ctx->sa) {
            fill_label_compat(fi, label);
            ctx->sa = label_value(label);
        }
        /* DA */
        if (g_strcmp0(abbrev, "wlan.da") == 0 && !ctx->da) {
            fill_label_compat(fi, label);
            ctx->da = label_value(label);
        }
        /* SSID - try both field names */
        if ((g_strcmp0(abbrev, "wlan.ssid") == 0 ||
             g_strcmp0(abbrev, "wlan_mgt.ssid") == 0) && !ctx->ssid) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) {
                ctx->ssid = val;
            } else {
                g_free(val);
            }
        }
        /* RSSI - prefer radiotap.dbm_antsignal */
        if (g_strcmp0(abbrev, "radiotap.dbm_antsignal") == 0 && !ctx->rssi_found) {
            ctx->rssi = (gint16)fvalue_get_sinteger(fi->value);
            ctx->rssi_found = TRUE;
        }
        /* Fallback RSSI from wlan_radio */
        if (g_strcmp0(abbrev, "wlan_radio.signal_dbm") == 0 && !ctx->rssi_found) {
            ctx->rssi = (gint16)fvalue_get_sinteger(fi->value);
            ctx->rssi_found = TRUE;
        }
        /* Channel */
        if (g_strcmp0(abbrev, "wlan_radio.channel") == 0 && ctx->channel == 0) {
            ctx->channel = (guint16)fvalue_get_uinteger(fi->value);
        }
        /* Frame type */
        if (g_strcmp0(abbrev, "wlan.fc.type") == 0) {
            ctx->fc_type = (guint8)fvalue_get_uinteger(fi->value);
            ctx->has_type = TRUE;
        }
        /* Frame subtype */
        if (g_strcmp0(abbrev, "wlan.fc.type_subtype") == 0) {
            ctx->fc_subtype = (guint8)fvalue_get_uinteger(fi->value);
        }
        /* Retry flag */
        if (g_strcmp0(abbrev, "wlan.fc.retry") == 0) {
            ctx->retry = (fvalue_get_uinteger(fi->value) != 0);
        }
        /* Reason code (deauth / disassoc management frames) */
        if (g_strcmp0(abbrev, "wlan.fixed.reason_code") == 0 && !ctx->reason_found) {
            ctx->reason_code = (guint16)fvalue_get_uinteger(fi->value);
            ctx->reason_found = TRUE;
        }
        /* PHY type for Wi-Fi standard identification */
        if (g_strcmp0(abbrev, "wlan_radio.phy") == 0 && !ctx->phy_found) {
            ctx->phy = (guint8)fvalue_get_uinteger(fi->value);
            ctx->phy_found = TRUE;
        }
    }

    /* Recurse into children */
    for (proto_node *child = node->first_child; child; child = child->next) {
        walk_wifi_proto_tree(child, ctx, depth + 1);
    }
}

/* Wi-Fi tap callback — processes one 802.11 frame.
 * Requires a proto tree (TL_REQUIRES_PROTO_TREE) so we walk the tree
 * to extract BSSID, TA/RA, RSSI, channel, etc. */
static tap_packet_status wifi_tap_packet_cb(void *tapdata, packet_info *pinfo,
                                            epan_dissect_t *edt,
                                            const void *data, tap_flags_t flags)
{
    tap_data_t *tap_data = (tap_data_t *)tapdata;
    static guint32 wifi_cb_count = 0;

    (void)data;
    (void)flags;

    if (!tap_data || !pinfo || !edt || !edt->tree)
        return TAP_PACKET_DONT_REDRAW;

    wifi_cb_count++;

    /* Walk the proto tree for Wi-Fi fields */
    wifi_frame_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    walk_wifi_proto_tree(edt->tree, &ctx, 0);

    /* Need at least a BSSID to build a pair */
    if (!ctx.bssid || !*ctx.bssid) {
        g_free(ctx.bssid); g_free(ctx.ta); g_free(ctx.ra);
        g_free(ctx.sa); g_free(ctx.da); g_free(ctx.ssid);
        return TAP_PACKET_DONT_REDRAW;
    }

    /* Determine the station (non-BSSID) address.
     * For data/management frames: the transmitter (TA) that is NOT the BSSID
     * is the station.  Fallback to SA/DA if TA/RA are absent.  */
    const gchar *station = NULL;
    gboolean station_is_sender = FALSE;  /* TRUE if station is the transmitter */

    if (ctx.ta && g_ascii_strcasecmp(ctx.ta, ctx.bssid) != 0) {
        /* TA is NOT the BSSID → station is the transmitter */
        station = ctx.ta;
        station_is_sender = TRUE;
    } else if (ctx.ra && g_ascii_strcasecmp(ctx.ra, ctx.bssid) != 0) {
        /* RA is NOT the BSSID → station is the receiver */
        station = ctx.ra;
        station_is_sender = FALSE;
    } else if (ctx.sa && g_ascii_strcasecmp(ctx.sa, ctx.bssid) != 0) {
        station = ctx.sa;
        station_is_sender = TRUE;
    } else if (ctx.da && g_ascii_strcasecmp(ctx.da, ctx.bssid) != 0) {
        station = ctx.da;
        station_is_sender = FALSE;
    }

    /* Skip broadcast-only frames where we can’t determine a station */
    if (!station) {
        /* Use BSSID as both ends for broadcast/beacon frames to at least count them */
        station = ctx.bssid;
        station_is_sender = FALSE;
    }

    if (wifi_cb_count <= 20) {
        ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING,
               "WiFi pkt %u: BSSID=%s STA=%s RSSI=%d ch=%u type=%u sub=%u retry=%d ssid=%s",
               wifi_cb_count, ctx.bssid, station,
               ctx.rssi_found ? ctx.rssi : -999, ctx.channel,
               ctx.fc_type, ctx.fc_subtype, ctx.retry,
               ctx.ssid ? ctx.ssid : "(null)");
    }

    /* Build pair: always station → BSSID direction as the canonical key */
    const gchar *pair_src = station;
    const gchar *pair_dst = ctx.bssid;

    comm_pair_t *pair = get_or_create_pair(tap_data->pairs_table,
                                            pair_src, pair_dst, TRUE);
    if (!pair) {
        g_free(ctx.bssid); g_free(ctx.ta); g_free(ctx.ra);
        g_free(ctx.sa); g_free(ctx.da); g_free(ctx.ssid);
        return TAP_PACKET_DONT_REDRAW;
    }

    /* Mark as Wi-Fi pair */
    pair->is_wifi = TRUE;

    /* Set BSSID / SSID (first-write wins) */
    if (!pair->wifi_bssid)
        pair->wifi_bssid = g_strdup(ctx.bssid);
    if (ctx.ssid && !pair->wifi_ssid)
        pair->wifi_ssid = g_strdup(ctx.ssid);

    /* RSSI aggregation */
    if (ctx.rssi_found) {
        if (pair->rssi_count == 0) {
            pair->rssi_min = ctx.rssi;
            pair->rssi_max = ctx.rssi;
        } else {
            if (ctx.rssi < pair->rssi_min) pair->rssi_min = ctx.rssi;
            if (ctx.rssi > pair->rssi_max) pair->rssi_max = ctx.rssi;
        }
        pair->rssi_sum += ctx.rssi;
        pair->rssi_count++;
    }

    /* Channel */
    if (ctx.channel > 0 && pair->wifi_channel == 0)
        pair->wifi_channel = ctx.channel;

    /* Frame type / subtype / retry */
    if (ctx.has_type) {
        pair->fc_type = ctx.fc_type;
        pair->fc_subtype = ctx.fc_subtype;

        /* Frame type counters */
        switch (ctx.fc_type) {
        case 0: pair->mgmt_frame_count++; break;  /* Management */
        case 1: pair->ctrl_frame_count++; break;  /* Control */
        case 2: pair->data_frame_count++; break;  /* Data */
        }

        /* Management subtype counters (type_subtype values) */
        switch (ctx.fc_subtype) {
        case 0x00: pair->assoc_req_count++;   break;  /* Association Request */
        case 0x01: pair->assoc_resp_count++;  break;  /* Association Response */
        case 0x02: pair->reassoc_req_count++; break;  /* Reassociation Request */
        case 0x04: pair->probe_req_count++;   break;  /* Probe Request */
        case 0x05: pair->probe_resp_count++;  break;  /* Probe Response */
        case 0x08: pair->beacon_count++;      break;  /* Beacon */
        case 0x0a: pair->disassoc_count++;    break;  /* Disassociation */
        case 0x0b: pair->auth_count++;        break;  /* Authentication */
        case 0x0c: pair->deauth_count++;      break;  /* Deauthentication */
        }

        /* Reason codes for deauth/disassoc */
        if (ctx.reason_found) {
            if (ctx.fc_subtype == 0x0c)  /* Deauthentication */
                pair->deauth_reason = ctx.reason_code;
            else if (ctx.fc_subtype == 0x0a)  /* Disassociation */
                pair->disassoc_reason = ctx.reason_code;
        }
    }
    if (ctx.retry)
        pair->retry_count++;

    /* PHY type (first-write wins to capture the primary standard) */
    if (ctx.phy_found && pair->wifi_phy == 0)
        pair->wifi_phy = ctx.phy;

    /* Packet / byte counts */
    pair->packet_count++;
    if (pinfo->fd) {
        guint32 pkt_len = pinfo->fd->pkt_len;
        if (pkt_len > 0)
            pair->byte_count += pkt_len;
    }

    /* Top protocol label */
    if (!pair->top_protocol)
        pair->top_protocol = g_strdup("802.11");

    /* Resolved display names: use station MAC / BSSID for now */
    if (!pair->resolved_src) {
        const gchar *resolved = address_to_display(wmem_epan_scope(), &(pinfo->dl_src));
        pair->resolved_src = g_strdup(resolved ? resolved : pair_src);
    }
    if (!pair->resolved_dst) {
        const gchar *resolved = address_to_display(wmem_epan_scope(), &(pinfo->dl_dst));
        pair->resolved_dst = g_strdup(resolved ? resolved : pair_dst);
    }

    /* MAC mappings */
    if (!pair->src_mac)
        pair->src_mac = g_strdup(pair_src);
    if (!pair->dst_mac)
        pair->dst_mac = g_strdup(pair_dst);

    /* Update protocol statistics */
    protocol_stats_t *stats = (protocol_stats_t *)g_hash_table_lookup(
        tap_data->protocols_table, "802.11");
    if (!stats) {
        stats = g_new0(protocol_stats_t, 1);
        stats->protocol_name = g_strdup("802.11");
        stats->color = 0x87CEEB;  /* Sky blue placeholder */
        stats->count = 0;
        g_hash_table_insert(tap_data->protocols_table, g_strdup("802.11"), stats);
    }
    if (pinfo->fd && pinfo->fd->pkt_len > 0)
        stats->count += pinfo->fd->pkt_len;

    /* Cleanup walk context */
    g_free(ctx.bssid); g_free(ctx.ta); g_free(ctx.ra);
    g_free(ctx.sa); g_free(ctx.da); g_free(ctx.ssid);

    return TAP_PACKET_DONT_REDRAW;
}

void packet_analyzer_init(void)
{
    init_protocol_colors();
}

void packet_analyzer_cleanup(void)
{
    if (protocol_colors) {
        g_hash_table_destroy(protocol_colors);
        protocol_colors = NULL;
    }
}

/* Tap reset callback */
static void circle_vis_tap_reset_cb(void *tapdata)
{
    tap_data_t *tap_data = (tap_data_t *)tapdata;
    if (!tap_data)
        return;

    /* Clear existing data */
    if (tap_data->pairs_table) {
        g_hash_table_remove_all(tap_data->pairs_table);
    }
    if (tap_data->protocols_table) {
        g_hash_table_remove_all(tap_data->protocols_table);
    }
}

/* Finish callback - called after all packets are processed */
static void circle_vis_tap_finish_cb(void *tapdata)
{
    tap_data_t *tap_data = (tap_data_t *)tapdata;
    /* Data collection is complete */
    /* Note: UI updates should happen on main thread, not from tap callback */
    (void)tap_data;
}

/* Register tap listener and process packets */
analysis_result_t* packet_analyzer_analyze(capture_file *cf, gboolean use_mac)
{
    static tap_data_t *s_tap_data = NULL;
    analysis_result_t *result;
    GHashTableIter iter;
    gpointer key, value;
    GString *error_string;

    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO, "packet_analyzer_analyze called: cf=%p, use_mac=%d", cf, use_mac);

    if (!cf) {
        ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING, "packet_analyzer_analyze: cf is NULL");
        /* Return empty result if no capture file */
        result = g_new0(analysis_result_t, 1);
        result->pairs = NULL;
        result->protocols = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, free_protocol_stats);
        result->total_packets = 0;
        result->total_bytes = 0;
        return result;
    }

    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO, "packet_analyzer_analyze: cf->state=%d, frames=%p, count=%u", 
           cf->state, cf->provider.frames, cf->count);

    /* Check if capture file is valid */
    if (cf->state == FILE_CLOSED || !cf->provider.frames) {
        ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING, "packet_analyzer_analyze: file not ready (state=%d, frames=%p)", 
               cf->state, cf->provider.frames);
        /* File not loaded or invalid - return empty result */
        result = g_new0(analysis_result_t, 1);
        result->pairs = NULL;
        result->protocols = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, free_protocol_stats);
        result->total_packets = 0;
        result->total_bytes = 0;
        return result;
    }

    /* Remove old tap listener if it exists */
    if (s_tap_data) {
        remove_tap_listener(s_tap_data);
        g_hash_table_destroy(s_tap_data->pairs_table);
        g_hash_table_destroy(s_tap_data->protocols_table);
        g_free(s_tap_data);
        s_tap_data = NULL;
    }

    /* Detect Wi-Fi monitor mode before allocating tap */
    gboolean is_wifi = detect_wifi_monitor_capture(cf);
    AnalysisMode mode = is_wifi ? ANALYSIS_MODE_WIFI
                                : (use_mac ? ANALYSIS_MODE_L2_MAC : ANALYSIS_MODE_L3_IP);
    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO,
           "Analysis mode: %s", is_wifi ? "WIFI" : (use_mac ? "L2_MAC" : "L3_IP"));

    /* Allocate tap data structure */
    s_tap_data = g_new0(tap_data_t, 1);
    s_tap_data->pairs_table = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, free_comm_pair);
    s_tap_data->protocols_table = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, free_protocol_stats);
    s_tap_data->use_mac = is_wifi ? TRUE : use_mac;  /* Wi-Fi always uses MAC */
    s_tap_data->mode = mode;

    /* Register tap listener for "frame" tap (all packets).
     * Wi-Fi mode needs a proto tree to walk for BSSID/RSSI/etc. */
    tap_packet_cb tap_cb = is_wifi ? wifi_tap_packet_cb : circle_vis_tap_packet_cb;
    guint tap_flags = is_wifi ? TL_REQUIRES_PROTO_TREE : TL_REQUIRES_NOTHING;
    error_string = register_tap_listener("frame", s_tap_data, NULL, 
                                        tap_flags,
                                        circle_vis_tap_reset_cb,
                                        tap_cb,
                                        NULL,  /* draw callback */
                                        circle_vis_tap_finish_cb); /* finish callback */

    if (error_string) {
        /* Tap registration failed */
        g_string_free(error_string, TRUE);
        g_hash_table_destroy(s_tap_data->pairs_table);
        g_hash_table_destroy(s_tap_data->protocols_table);
        g_free(s_tap_data);
        s_tap_data = NULL;
        /* Return empty result on error */
        result = g_new0(analysis_result_t, 1);
        result->pairs = NULL;
        result->protocols = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, free_protocol_stats);
        result->total_packets = 0;
        result->total_bytes = 0;
        return result;
    }

    /* Process packets directly from frame_data for already-loaded files */
    /* This will populate our hash tables with communication pairs */
    /* Use lightweight dissection (no proto tree) to avoid memory issues with large files */
    if (cf->state == FILE_READ_DONE && cf->provider.frames && cf->count > 0) {
        frame_data *fdata;
        guint32 framenum;
        epan_dissect_t *edt;
        wtap_rec rec;
        int err;
        gchar *err_info;
        guint32 processed_count = 0;
        const guint32 BATCH_SIZE = 100; /* Process in batches to avoid UI freezing */
        
        /* Initialize dissector:
         * - Wi-Fi mode needs TRUE, TRUE to build a proto tree for our walker.
         * - Normal mode uses FALSE, FALSE (lightweight) to save memory. */
        gboolean need_tree = is_wifi;
        edt = epan_dissect_new(cf->epan, need_tree, need_tree);
        
        /* Check if display filter is set - only process matching packets */
        /* frame_data->passed_dfilter indicates if the frame passed the display filter */
        gboolean has_filter = (cf->dfilter != NULL);
        guint32 filtered_count = 0;
        if (has_filter) {
            ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO, "Display filter is active - only processing matching packets");
        } else {
            ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO, "No display filter - processing all packets");
        }
        
        /* Iterate through all frames and process them in batches */
        for (framenum = 1; framenum <= cf->count; framenum++) {
            fdata = frame_data_sequence_find(cf->provider.frames, framenum);
            if (fdata && fdata->file_off >= 0) {
                /* If display filter is set, check if this packet matches before processing */
                if (has_filter) {
                    /* Check if frame is marked as passing the display filter */
                    /* frame_data has a 'passed_dfilter' flag that indicates if it matches */
                    if (!fdata->passed_dfilter) {
                        /* Skip this packet - it doesn't match the display filter */
                        filtered_count++;
                        continue;
                    }
                }
                
                /* Initialize rec and read packet data from file.
                 * The API differs between Wireshark 4.4.x and 4.6+. */
#if VERSION_MINOR >= 6
                /* Wireshark 4.6+ API: buffer is embedded in wtap_rec */
                wtap_rec_init(&rec, fdata->cap_len);
                
                if (wtap_seek_read(cf->provider.wth, fdata->file_off, &rec, &err, &err_info)) {
                    int file_type_subtype = wtap_file_type_subtype(cf->provider.wth);
                    epan_dissect_run_with_taps(edt, file_type_subtype, &rec, fdata, NULL);
                    epan_dissect_reset(edt);  /* Free proto-tree / pinfo for this frame */
                    processed_count++;
                    
                    if (processed_count % BATCH_SIZE == 0) {
            circle_vis_pump_events();
                    }
                } else {
                    if (err_info) {
                        g_free(err_info);
                        err_info = NULL;
                    }
                }
                
                wtap_rec_cleanup(&rec);
#else
                /* Wireshark 4.4.x API: separate Buffer, tvbuff_t required */
                {
                    Buffer buf;
                    ws_buffer_init(&buf, fdata->cap_len);
                    wtap_rec_init(&rec);
                    
                    if (wtap_seek_read(cf->provider.wth, fdata->file_off, &rec, &buf, &err, &err_info)) {
                        int file_type_subtype = wtap_file_type_subtype(cf->provider.wth);
                        tvbuff_t *tvb = tvb_new_real_data(ws_buffer_start_ptr(&buf),
                                                          rec.rec_header.packet_header.caplen,
                                                          rec.rec_header.packet_header.len);
                        epan_dissect_run_with_taps(edt, file_type_subtype, &rec, tvb, fdata, NULL);
                        epan_dissect_reset(edt);  /* Free proto-tree / pinfo for this frame */
                        processed_count++;
                        
                        if (processed_count % BATCH_SIZE == 0) {
#ifdef __cplusplus
                            QApplication::processEvents();
#endif
                        }
                    } else {
                        if (err_info) {
                            g_free(err_info);
                            err_info = NULL;
                        }
                    }
                    
                    wtap_rec_cleanup(&rec);
                    ws_buffer_free(&buf);
                }
#endif
            }
        }
        
        epan_dissect_free(edt);
        
        /* Log how many packets were processed */
        if (has_filter) {
            ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING, "Processed %u packets out of %u total (%u filtered out by display filter)", 
                   processed_count, cf->count, filtered_count);
        } else {
            ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING, "Processed %u packets out of %u total", processed_count, cf->count);
        }
        
        /* Log hash table sizes */
        guint pairs_count = g_hash_table_size(s_tap_data->pairs_table);
        guint protocols_count = g_hash_table_size(s_tap_data->protocols_table);
        ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING, "Collected %u pairs and %u protocols", pairs_count, protocols_count);
    } else {
        ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING, "Skipping packet processing: state=%d, frames=%p, count=%u", 
               cf->state, cf->provider.frames, cf->count);
    }

    /* Create result structure from collected data */
    result = g_new0(analysis_result_t, 1);
    result->pairs = NULL;
    /* Create a copy of the protocols table so result owns it independently */
    result->protocols = copy_protocols_table(s_tap_data->protocols_table);
    result->total_packets = 0;
    result->total_bytes = 0;
    result->mode = mode;

    /* Convert hash table to list */
    guint pairs_in_table = g_hash_table_size(s_tap_data->pairs_table);
    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO, "Converting %u pairs from hash table to list", pairs_in_table);
    
    /* Collect all pairs first, then remove them from hash table to transfer ownership */
    GList *pairs_to_transfer = NULL;
    g_hash_table_iter_init(&iter, s_tap_data->pairs_table);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        comm_pair_t *pair = (comm_pair_t *)value;
        /* Ensure top_protocol is always set to a valid value - check for "<Missing Protocol Name>" too */
        if (!pair->top_protocol || !*pair->top_protocol ||
            g_strcmp0(pair->top_protocol, "<Missing Protocol Name>") == 0 ||
            g_strstr_len(pair->top_protocol, -1, "Missing") != NULL) {
            if (pair->top_protocol) {
                g_free(pair->top_protocol);
            }
            pair->top_protocol = g_strdup("Unknown");
            ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING, "Pair %s->%s had invalid top_protocol, set to Unknown", 
                   pair->src_addr ? pair->src_addr : "NULL", pair->dst_addr ? pair->dst_addr : "NULL");
        }
        pairs_to_transfer = g_list_append(pairs_to_transfer, pair);
    }
    
    /* Remove pairs from hash table (but don't free them - we're transferring ownership) */
    /* We need to temporarily disable the destructor, or remove entries manually */
    for (GList *piter = pairs_to_transfer; piter; piter = piter->next) {
        comm_pair_t *pair = (comm_pair_t *)piter->data;
        /* Find and remove the key for this pair */
        g_hash_table_iter_init(&iter, s_tap_data->pairs_table);
        while (g_hash_table_iter_next(&iter, &key, &value)) {
            if (value == pair) {
                g_hash_table_steal(s_tap_data->pairs_table, key);
                g_free(key);  /* Free the key string */
                break;
            }
        }
    }
    
    /* Now build result list from transferred pairs */
    for (GList *piter = pairs_to_transfer; piter; piter = piter->next) {
        comm_pair_t *pair = (comm_pair_t *)piter->data;
        /* Final validation - ensure top_protocol is valid */
        if (!pair->top_protocol || !*pair->top_protocol) {
            if (pair->top_protocol) {
                g_free(pair->top_protocol);
            }
            pair->top_protocol = g_strdup("Unknown");
        }
        result->pairs = g_list_append(result->pairs, pair);
        result->total_packets += pair->packet_count;
        result->total_bytes += pair->byte_count;
    }
    
    /* Free the temporary list (but not the pairs - they're now in result->pairs) */
    g_list_free(pairs_to_transfer);
    
    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO, "Result: %u pairs, %" G_GUINT64_FORMAT " total packets, %" G_GUINT64_FORMAT " total bytes", 
           g_list_length(result->pairs), result->total_packets, result->total_bytes);

    /* Note: pairs have been removed from pairs_table and transferred to result->pairs */
    /* The tap listener will remain registered until next analyze call */

    return result;
}

void packet_analyzer_free_result(analysis_result_t *result)
{
    if (!result)
        return;

    /* Free pairs list if it exists */
    if (result->pairs) {
        g_list_free_full(result->pairs, free_comm_pair);
        result->pairs = NULL;
    }

    /* Free protocols hash table if it exists */
    /* g_hash_table_destroy will automatically call free_protocol_stats for each value */
    if (result->protocols) {
        g_hash_table_destroy(result->protocols);
        result->protocols = NULL;
    }

    g_free(result);
}

GList* packet_analyzer_get_top_pairs(analysis_result_t *result, guint top_n, gboolean use_bytes)
{
    GList *top_list = NULL;
    GList *iter;
    guint i, j;
    comm_pair_t **pair_array;
    guint pair_count;
    comm_pair_t *temp_pair;

    if (!result || !result->pairs)
        return NULL;

    /* Count pairs */
    pair_count = g_list_length(result->pairs);
    if (pair_count == 0)
        return NULL;

    /* Allocate array to hold pair pointers */
    pair_array = g_new(comm_pair_t*, pair_count);
    
    /* Copy pair pointers to array */
    i = 0;
    for (iter = result->pairs; iter; iter = iter->next, i++) {
        pair_array[i] = (comm_pair_t *)iter->data;
    }

    /* Simple selection sort to get top N (more efficient than full sort for small N) */
    guint n_to_sort = (top_n < pair_count) ? top_n : pair_count;
    for (i = 0; i < n_to_sort; i++) {
        guint max_idx = i;
        for (j = i + 1; j < pair_count; j++) {
            gboolean j_is_greater = FALSE;
            if (use_bytes) {
                j_is_greater = (pair_array[j]->byte_count > pair_array[max_idx]->byte_count);
            } else {
                j_is_greater = (pair_array[j]->packet_count > pair_array[max_idx]->packet_count);
            }
            if (j_is_greater) {
                max_idx = j;
            }
        }
        /* Swap */
        if (max_idx != i) {
            temp_pair = pair_array[i];
            pair_array[i] = pair_array[max_idx];
            pair_array[max_idx] = temp_pair;
        }
    }

    /* Build result list from top N */
    for (i = 0; i < n_to_sort; i++) {
        top_list = g_list_append(top_list, pair_array[i]);
    }

    /* Free the array */
    g_free(pair_array);
    
    return top_list;
}

/* ------------------------------------------------------------------ */
/* TLS Information Extraction                                         */
/* ------------------------------------------------------------------ */

static void free_tls_cert_info(gpointer data)
{
    tls_cert_info_t *cert = (tls_cert_info_t *)data;
    if (!cert) return;
    g_free(cert->subject_cn);
    g_free(cert->issuer_cn);
    g_free(cert->not_before);
    g_free(cert->not_after);
    g_free(cert->serial_number);
    if (cert->san_dns_names)
        g_list_free_full(cert->san_dns_names, g_free);
    g_free(cert);
}

void packet_analyzer_free_tls_info(tls_info_t *info)
{
    if (!info) return;
    g_free(info->version);
    g_free(info->cipher_suite);
    g_free(info->sni);
    g_free(info->alpn);
    g_free(info->sig_algorithm);
    g_free(info->ja4);
    g_free(info->ja4s);
    if (info->certificates)
        g_list_free_full(info->certificates, free_tls_cert_info);
    g_free(info);
}

/* Context used while recursively walking the protocol tree */
typedef struct {
    tls_info_t     *info;
    tls_cert_info_t *cur_cert;   /* certificate currently being parsed */
    gboolean        in_subject;
    gboolean        in_issuer;
    gboolean        in_validity;
    gboolean        in_san;
    int             cert_index;  /* how many certificates we've seen */
} tls_walk_ctx_t;

/* Portable wrapper around proto_item_fill_label() which gained a third
 * parameter (value_offset) in Wireshark 4.6.                          */
static void fill_label_compat(field_info *fi, gchar *buf)
{
#if VERSION_MINOR >= 6
    size_t val_off = 0;
    proto_item_fill_label(fi, buf, &val_off);
#else
    proto_item_fill_label(fi, buf);
#endif
}

/* Extract the value portion after ": " from a label produced by
 * proto_item_fill_label(), e.g. "Version: TLS 1.2 (0x0303)" → "TLS 1.2 (0x0303)" */
static gchar* label_value(const gchar *label)
{
    const gchar *sep = strstr(label, ": ");
    if (sep)
        return g_strdup(sep + 2);
    return g_strdup(label);
}

/* Recursive proto-tree walker that collects TLS / X.509 fields. */
static void walk_tls_proto_tree(proto_node *node, tls_walk_ctx_t *ctx, int depth)
{
    if (!node || depth > 60) return;

    field_info *fi = node->finfo;
    if (fi && fi->hfinfo && fi->hfinfo->abbrev) {
        const gchar *abbrev = fi->hfinfo->abbrev;
        const gchar *name   = fi->hfinfo->name ? fi->hfinfo->name : "";
        gchar label[ITEM_LABEL_LENGTH];
        label[0] = '\0';

        /* ---- TLS supported_versions extension (authoritative for TLS 1.3) ----
         * In TLS 1.3 the record-layer and handshake version fields are frozen
         * at 0x0301 / 0x0303 for backward compatibility.  The *real* negotiated
         * version lives in the supported_versions extension of the Server Hello.
         * This field also appears (multiple times) in the Client Hello, but the
         * Server Hello entry comes last, so always overwriting gives us the
         * negotiated version. */
        if (g_strcmp0(abbrev, "tls.handshake.extensions.supported_version") == 0) {
            fill_label_compat(fi, label);
            g_free(ctx->info->version);   /* may replace an earlier value */
            ctx->info->version = label_value(label);
        }

        /* ---- TLS Handshake Version ---- */
        if (g_strcmp0(abbrev, "tls.handshake.version") == 0 && !ctx->info->version) {
            fill_label_compat(fi, label);
            ctx->info->version = label_value(label);
        }

        /* ---- TLS Record Version (fallback when handshake version is missing) ---- */
        if (g_strcmp0(abbrev, "tls.record.version") == 0 && !ctx->info->version) {
            fill_label_compat(fi, label);
            ctx->info->version = label_value(label);
        }

        /* ---- TLS Cipher Suite (Server Hello) ---- */
        if (g_strcmp0(abbrev, "tls.handshake.ciphersuite") == 0 && !ctx->info->cipher_suite) {
            fill_label_compat(fi, label);
            ctx->info->cipher_suite = label_value(label);
        }

        /* ---- SNI (Server Name Indication) ---- */
        if (g_strcmp0(abbrev, "tls.handshake.extensions_server_name") == 0 && !ctx->info->sni) {
            fill_label_compat(fi, label);
            ctx->info->sni = label_value(label);
        }

        /* ---- ALPN (Application-Layer Protocol Negotiation) ----
         * Take the first value seen (client's preferred protocol). */
        if (g_strcmp0(abbrev, "tls.handshake.extensions_alpn_str") == 0 && !ctx->info->alpn) {
            fill_label_compat(fi, label);
            ctx->info->alpn = label_value(label);
        }

        /* ---- Signature Algorithm ----
         * Always overwrite: in TLS 1.2 the last occurrence is from
         * ServerKeyExchange (the server's actual choice). */
        if (g_strcmp0(abbrev, "tls.handshake.sig_hash_alg") == 0) {
            fill_label_compat(fi, label);
            g_free(ctx->info->sig_algorithm);
            ctx->info->sig_algorithm = label_value(label);
        }

        /* ---- JA4 client fingerprint (native Wireshark ≥ 4.4) ---- */
        if (g_strcmp0(abbrev, "tls.handshake.ja4") == 0 && !ctx->info->ja4) {
            fill_label_compat(fi, label);
            ctx->info->ja4 = label_value(label);
        }

        /* ---- JA4S server fingerprint (FoxIO JA4+ plugin) ---- */
        if (g_strcmp0(abbrev, "ja4.ja4s") == 0 && !ctx->info->ja4s) {
            fill_label_compat(fi, label);
            ctx->info->ja4s = label_value(label);
        }

        /* ---- Handshake type counter ---- */
        if (g_strcmp0(abbrev, "tls.handshake.type") == 0) {
            ctx->info->handshake_count++;
        }

        /* ---- Certificate boundary ----
         * Each "signedCertificate" node marks a new X.509 cert in the chain. */
        if (g_strcmp0(abbrev, "x509af.signedCertificate") == 0) {
            tls_cert_info_t *cert = g_new0(tls_cert_info_t, 1);
            ctx->info->certificates = g_list_append(ctx->info->certificates, cert);
            ctx->cur_cert = cert;
            ctx->cert_index++;
            ctx->in_subject = FALSE;
            ctx->in_issuer  = FALSE;
        }

        /* ---- Track subject / issuer / validity / SAN context ---- */
        if (g_strcmp0(name, "subject") == 0 || g_strcmp0(abbrev, "x509af.subject") == 0) {
            ctx->in_subject  = TRUE;
            ctx->in_issuer   = FALSE;
        }
        if (g_strcmp0(name, "issuer") == 0 || g_strcmp0(abbrev, "x509af.issuer") == 0) {
            ctx->in_issuer   = TRUE;
            ctx->in_subject  = FALSE;
        }
        if (g_strcmp0(name, "validity") == 0 || g_strcmp0(abbrev, "x509af.validity") == 0) {
            ctx->in_validity = TRUE;
        }
        if (strstr(abbrev, "subjectAltName") || strstr(name, "SubjectAltName")) {
            ctx->in_san = TRUE;
        }

        /* ---- Certificate serial number ---- */
        if (ctx->cur_cert && !ctx->cur_cert->serial_number &&
            (g_strcmp0(abbrev, "x509af.serialNumber") == 0 ||
             strstr(abbrev, "signedCertificate.serialNumber"))) {
            fill_label_compat(fi, label);
            ctx->cur_cert->serial_number = label_value(label);
        }

        /* ---- Validity dates ---- */
        if (ctx->cur_cert && ctx->in_validity &&
            (g_strcmp0(abbrev, "x509af.utcTime") == 0 ||
             g_strcmp0(abbrev, "x509af.generalizedTime") == 0)) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (!ctx->cur_cert->not_before) {
                ctx->cur_cert->not_before = val;
            } else if (!ctx->cur_cert->not_after) {
                ctx->cur_cert->not_after = val;
            } else {
                g_free(val);
            }
        }

        /* ---- RDN items: parse "id-at-commonName=..." representation ----
         * RelativeDistinguishedName items carry the OID interpretation in
         * parentheses, e.g. "(id-at-commonName=example.com)".               */
        if (ctx->cur_cert &&
            (strstr(abbrev, "RelativeDistinguishedName") ||
             g_strcmp0(abbrev, "x509if.RelativeDistinguishedName_item") == 0)) {
            if (fi->rep && fi->rep->representation[0]) {
                const gchar *rep = fi->rep->representation;
                const gchar *cn_marker = strstr(rep, "id-at-commonName=");
                const gchar *org_marker = strstr(rep, "id-at-organizationName=");
                if (cn_marker) {
                    const gchar *val_start = cn_marker + strlen("id-at-commonName=");
                    /* Value runs until ')' or end of string */
                    const gchar *val_end = strchr(val_start, ')');
                    gchar *cn = val_end
                        ? g_strndup(val_start, (gsize)(val_end - val_start))
                        : g_strdup(val_start);
                    if (ctx->in_subject && !ctx->cur_cert->subject_cn) {
                        ctx->cur_cert->subject_cn = cn;
                    } else if (ctx->in_issuer && !ctx->cur_cert->issuer_cn) {
                        ctx->cur_cert->issuer_cn = cn;
                    } else {
                        g_free(cn);
                    }
                }
                if (org_marker && ctx->in_issuer && !ctx->cur_cert->issuer_cn) {
                    const gchar *val_start = org_marker + strlen("id-at-organizationName=");
                    const gchar *val_end = strchr(val_start, ')');
                    ctx->cur_cert->issuer_cn = val_end
                        ? g_strndup(val_start, (gsize)(val_end - val_start))
                        : g_strdup(val_start);
                }
            }
        }

        /* ---- SAN DNS names ---- */
        if (ctx->cur_cert && ctx->in_san &&
            g_strcmp0(abbrev, "x509ce.dNSName") == 0) {
            fill_label_compat(fi, label);
            gchar *dns = label_value(label);
            if (dns && *dns) {
                ctx->cur_cert->san_dns_names =
                    g_list_append(ctx->cur_cert->san_dns_names, dns);
            } else {
                g_free(dns);
            }
        }
    }

    /* Recurse into children */
    for (proto_node *child = node->first_child; child; child = child->next) {
        walk_tls_proto_tree(child, ctx, depth + 1);
    }

    /* Reset context flags when leaving tracked subtrees */
    if (fi && fi->hfinfo) {
        const gchar *name = fi->hfinfo->name ? fi->hfinfo->name : "";
        if (g_strcmp0(name, "validity") == 0 || g_strcmp0(fi->hfinfo->abbrev, "x509af.validity") == 0)
            ctx->in_validity = FALSE;
        if (strstr(fi->hfinfo->abbrev, "subjectAltName") || strstr(name, "SubjectAltName"))
            ctx->in_san = FALSE;
    }
}

tls_info_t* packet_analyzer_extract_tls_info(capture_file *cf,
                                             const gchar *addr_a,
                                             const gchar *addr_b,
                                             guint16 port,
                                             gboolean addr_is_mac)
{
    tls_info_t *info = g_new0(tls_info_t, 1);

    if (!cf || cf->state != FILE_READ_DONE || !cf->provider.frames || cf->count == 0) {
        ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING, "extract_tls_info: capture not ready");
        return info;
    }

    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING,
           "TLS analysis: addr_a=%s, addr_b=%s, port=%u, is_mac=%d",
           addr_a ? addr_a : "(null)", addr_b ? addr_b : "(null)",
           port, addr_is_mac);
    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING,
           "TLS analysis: cf->state=%d, cf->count=%u",
           cf->state, cf->count);

    /* Iterate frames with full dissection.
     * We match packets by comparing addresses and port directly from the
     * dissected pinfo struct, rather than using dfilter_apply_edt(),
     * because display-filter matching is unreliable during re-dissection
     * of an already-loaded capture file. */
    tls_walk_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.info = info;

    epan_dissect_t *edt = epan_dissect_new(cf->epan, TRUE, TRUE);

    guint32 matched = 0;
    for (guint32 framenum = 1; framenum <= cf->count; framenum++) {
        frame_data *fdata = frame_data_sequence_find(cf->provider.frames, framenum);
        if (!fdata || fdata->file_off < 0)
            continue;

        int err = 0;
        gchar *err_info_str = NULL;
        wtap_rec rec;
        gboolean read_ok;

#if VERSION_MINOR >= 6
        wtap_rec_init(&rec, fdata->cap_len);
        read_ok = wtap_seek_read(cf->provider.wth, fdata->file_off, &rec, &err, &err_info_str);
        if (read_ok) {
            int fts = wtap_file_type_subtype(cf->provider.wth);
            epan_dissect_run(edt, fts, &rec, fdata, NULL);
#else
        {
            Buffer buf;
            ws_buffer_init(&buf, fdata->cap_len);
            wtap_rec_init(&rec);
            read_ok = wtap_seek_read(cf->provider.wth, fdata->file_off, &rec, &buf, &err, &err_info_str);
            if (read_ok) {
                int fts = wtap_file_type_subtype(cf->provider.wth);
                tvbuff_t *tvb = tvb_new_real_data(ws_buffer_start_ptr(&buf),
                                                  rec.rec_header.packet_header.caplen,
                                                  rec.rec_header.packet_header.len);
                epan_dissect_run(edt, fts, &rec, tvb, fdata, NULL);
#endif
                /* Match addresses and port directly from pinfo */
                {
                    gchar pkt_src[MAX_ADDR_STR_LEN], pkt_dst[MAX_ADDR_STR_LEN];
                    if (addr_is_mac) {
                        address_to_str_buf(&edt->pi.dl_src, pkt_src, sizeof(pkt_src));
                        address_to_str_buf(&edt->pi.dl_dst, pkt_dst, sizeof(pkt_dst));
                    } else {
                        address_to_str_buf(&edt->pi.net_src, pkt_src, sizeof(pkt_src));
                        address_to_str_buf(&edt->pi.net_dst, pkt_dst, sizeof(pkt_dst));
                    }
                    gboolean addr_ok =
                        (g_strcmp0(pkt_src, addr_a) == 0 && g_strcmp0(pkt_dst, addr_b) == 0) ||
                        (g_strcmp0(pkt_src, addr_b) == 0 && g_strcmp0(pkt_dst, addr_a) == 0);
                    gboolean port_ok =
                        ((guint32)port == edt->pi.srcport || (guint32)port == edt->pi.destport);

                    if (addr_ok && port_ok) {
                        matched++;
                        walk_tls_proto_tree(edt->tree, &ctx, 0);
                    }
                }

                epan_dissect_reset(edt);
#if VERSION_MINOR >= 6
        }
        wtap_rec_cleanup(&rec);
#else
            }
            wtap_rec_cleanup(&rec);
            ws_buffer_free(&buf);
        }
#endif
        if (err_info_str) {
            g_free(err_info_str);
        }

        if (matched % 50 == 0)
            circle_vis_pump_events();
    }

    epan_dissect_free(edt);

    info->matched_packets = matched;
    info->found = (matched > 0 && (info->sni || info->version ||
                                    info->cipher_suite || info->certificates ||
                                    info->handshake_count > 0));

    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING,
           "TLS analysis done: %u packets matched, found=%d, handshakes=%u, "
           "version=%s, cipher=%s, sni=%s, certs=%u",
           matched, info->found, info->handshake_count,
           info->version ? info->version : "(none)",
           info->cipher_suite ? info->cipher_suite : "(none)",
           info->sni ? info->sni : "(none)",
           info->certificates ? g_list_length(info->certificates) : 0);

    return info;
}

/* ------------------------------------------------------------------ */
/* HTTP Information Extraction                                         */
/* ------------------------------------------------------------------ */

static void free_http_request_entry(gpointer data)
{
    http_request_entry_t *req = (http_request_entry_t *)data;
    if (!req) return;
    g_free(req->method);
    g_free(req->uri);
    g_free(req->host);
    g_free(req);
}

void packet_analyzer_free_http_info(http_info_t *info)
{
    if (!info) return;
    if (info->hosts)         g_list_free_full(info->hosts, g_free);
    if (info->user_agents)   g_list_free_full(info->user_agents, g_free);
    if (info->servers)       g_list_free_full(info->servers, g_free);
    if (info->content_types) g_list_free_full(info->content_types, g_free);
    if (info->requests)      g_list_free_full(info->requests, free_http_request_entry);
    if (info->status_codes)  g_hash_table_destroy(info->status_codes);
    g_free(info);
}

/* Helper: add a string to a GList only if not already present */
static void add_unique_string(GList **list, const gchar *str)
{
    if (!str || !*str) return;
    for (GList *l = *list; l; l = l->next) {
        if (g_strcmp0((const gchar *)l->data, str) == 0) return;
    }
    *list = g_list_append(*list, g_strdup(str));
}

/* Context for the HTTP proto-tree walker */
typedef struct {
    http_info_t         *info;
    http_request_entry_t *cur_req;   /* request currently being populated */
} http_walk_ctx_t;

/* Recursive proto-tree walker that collects HTTP fields. */
static void walk_http_proto_tree(proto_node *node, http_walk_ctx_t *ctx, int depth)
{
    if (!node || depth > 40) return;

    field_info *fi = node->finfo;
    if (fi && fi->hfinfo && fi->hfinfo->abbrev) {
        const gchar *abbrev = fi->hfinfo->abbrev;
        gchar label[ITEM_LABEL_LENGTH];
        label[0] = '\0';

        /* ---- Request Method ---- */
        if (g_strcmp0(abbrev, "http.request.method") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            http_request_entry_t *req = g_new0(http_request_entry_t, 1);
            req->method = val;
            ctx->info->requests = g_list_append(ctx->info->requests, req);
            ctx->cur_req = req;
            ctx->info->request_count++;
        }

        /* ---- Request URI ---- */
        if (g_strcmp0(abbrev, "http.request.uri") == 0 && ctx->cur_req && !ctx->cur_req->uri) {
            fill_label_compat(fi, label);
            ctx->cur_req->uri = label_value(label);
        }

        /* ---- Host header ---- */
        if (g_strcmp0(abbrev, "http.host") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            add_unique_string(&ctx->info->hosts, val);
            if (ctx->cur_req && !ctx->cur_req->host)
                ctx->cur_req->host = g_strdup(val);
            g_free(val);
        }

        /* ---- User-Agent ---- */
        if (g_strcmp0(abbrev, "http.user_agent") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            add_unique_string(&ctx->info->user_agents, val);
            g_free(val);
        }

        /* ---- Response Status Code ---- */
        if (g_strcmp0(abbrev, "http.response.code") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            ctx->info->response_count++;
            /* Increment count in status_codes hash table */
            gpointer existing = g_hash_table_lookup(ctx->info->status_codes, val);
            guint count = existing ? GPOINTER_TO_UINT(existing) : 0;
            g_hash_table_insert(ctx->info->status_codes, g_strdup(val),
                                GUINT_TO_POINTER(count + 1));
            /* Reset cur_req — we're now in a response */
            ctx->cur_req = NULL;
            g_free(val);
        }

        /* ---- Server header ---- */
        if (g_strcmp0(abbrev, "http.server") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            add_unique_string(&ctx->info->servers, val);
            g_free(val);
        }

        /* ---- Content-Type ---- */
        if (g_strcmp0(abbrev, "http.content_type") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            add_unique_string(&ctx->info->content_types, val);
            g_free(val);
        }
    }

    /* Recurse into children */
    for (proto_node *child = node->first_child; child; child = child->next) {
        walk_http_proto_tree(child, ctx, depth + 1);
    }
}

http_info_t* packet_analyzer_extract_http_info(capture_file *cf,
                                               const gchar *addr_a,
                                               const gchar *addr_b,
                                               guint16 port,
                                               gboolean addr_is_mac)
{
    http_info_t *info = g_new0(http_info_t, 1);
    info->status_codes = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);

    if (!cf || cf->state != FILE_READ_DONE || !cf->provider.frames || cf->count == 0) {
        return info;
    }

    http_walk_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.info = info;

    epan_dissect_t *edt = epan_dissect_new(cf->epan, TRUE, TRUE);

    guint32 matched = 0;
    for (guint32 framenum = 1; framenum <= cf->count; framenum++) {
        frame_data *fdata = frame_data_sequence_find(cf->provider.frames, framenum);
        if (!fdata || fdata->file_off < 0)
            continue;

        int err = 0;
        gchar *err_info_str = NULL;
        wtap_rec rec;
        gboolean read_ok;

#if VERSION_MINOR >= 6
        wtap_rec_init(&rec, fdata->cap_len);
        read_ok = wtap_seek_read(cf->provider.wth, fdata->file_off, &rec, &err, &err_info_str);
        if (read_ok) {
            int fts = wtap_file_type_subtype(cf->provider.wth);
            epan_dissect_run(edt, fts, &rec, fdata, NULL);
#else
        {
            Buffer buf;
            ws_buffer_init(&buf, fdata->cap_len);
            wtap_rec_init(&rec);
            read_ok = wtap_seek_read(cf->provider.wth, fdata->file_off, &rec, &buf, &err, &err_info_str);
            if (read_ok) {
                int fts = wtap_file_type_subtype(cf->provider.wth);
                tvbuff_t *tvb = tvb_new_real_data(ws_buffer_start_ptr(&buf),
                                                  rec.rec_header.packet_header.caplen,
                                                  rec.rec_header.packet_header.len);
                epan_dissect_run(edt, fts, &rec, tvb, fdata, NULL);
#endif
                /* Match addresses and port directly from pinfo */
                {
                    gchar pkt_src[MAX_ADDR_STR_LEN], pkt_dst[MAX_ADDR_STR_LEN];
                    if (addr_is_mac) {
                        address_to_str_buf(&edt->pi.dl_src, pkt_src, sizeof(pkt_src));
                        address_to_str_buf(&edt->pi.dl_dst, pkt_dst, sizeof(pkt_dst));
                    } else {
                        address_to_str_buf(&edt->pi.net_src, pkt_src, sizeof(pkt_src));
                        address_to_str_buf(&edt->pi.net_dst, pkt_dst, sizeof(pkt_dst));
                    }
                    gboolean addr_ok =
                        (g_strcmp0(pkt_src, addr_a) == 0 && g_strcmp0(pkt_dst, addr_b) == 0) ||
                        (g_strcmp0(pkt_src, addr_b) == 0 && g_strcmp0(pkt_dst, addr_a) == 0);
                    gboolean port_ok =
                        ((guint32)port == edt->pi.srcport || (guint32)port == edt->pi.destport);

                    if (addr_ok && port_ok) {
                        matched++;
                        ctx.cur_req = NULL; /* reset per-frame */
                        walk_http_proto_tree(edt->tree, &ctx, 0);
                    }
                }

                epan_dissect_reset(edt);
#if VERSION_MINOR >= 6
        }
        wtap_rec_cleanup(&rec);
#else
            }
            wtap_rec_cleanup(&rec);
            ws_buffer_free(&buf);
        }
#endif
        if (err_info_str) {
            g_free(err_info_str);
        }

        if (matched % 50 == 0)
            circle_vis_pump_events();
    }

    epan_dissect_free(edt);

    info->matched_packets = matched;
    info->found = (info->request_count > 0 || info->response_count > 0);

    return info;
}

/* ------------------------------------------------------------------ */
/* SMB / CIFS Information Extraction                                    */
/* ------------------------------------------------------------------ */

void packet_analyzer_free_smb_info(smb_info_t *info)
{
    if (!info) return;
    g_free(info->dialect);
    g_free(info->native_os);
    g_free(info->native_lanman);
    g_free(info->auth_domain);
    g_free(info->auth_username);
    g_free(info->auth_hostname);
    g_free(info->target_name);
    if (info->tree_paths)        g_list_free_full(info->tree_paths, g_free);
    if (info->filenames)         g_list_free_full(info->filenames, g_free);
    if (info->named_pipes)       g_list_free_full(info->named_pipes, g_free);
    if (info->dcerpc_interfaces) g_list_free_full(info->dcerpc_interfaces, g_free);
    if (info->cmd_counts)        g_hash_table_destroy(info->cmd_counts);
    g_free(info);
}

/* Context for the SMB proto-tree walker */
typedef struct {
    smb_info_t *info;
} smb_walk_ctx_t;

/* Recursive proto-tree walker that collects SMB / NTLMSSP / DCE-RPC fields. */
static void walk_smb_proto_tree(proto_node *node, smb_walk_ctx_t *ctx, int depth)
{
    if (!node || depth > 60) return;

    field_info *fi = node->finfo;
    if (fi && fi->hfinfo && fi->hfinfo->abbrev) {
        const gchar *abbrev = fi->hfinfo->abbrev;
        gchar label[ITEM_LABEL_LENGTH];
        label[0] = '\0';

        /* ---- SMB2 Dialect ---- */
        if (g_strcmp0(abbrev, "smb2.dialect") == 0) {
            fill_label_compat(fi, label);
            g_free(ctx->info->dialect);
            ctx->info->dialect = label_value(label);
            ctx->info->is_smb2 = TRUE;
        }

        /* ---- SMB2 Command (for stats) ---- */
        if (g_strcmp0(abbrev, "smb2.cmd") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) {
                gpointer existing = g_hash_table_lookup(ctx->info->cmd_counts, val);
                guint count = existing ? GPOINTER_TO_UINT(existing) : 0;
                g_hash_table_insert(ctx->info->cmd_counts, g_strdup(val),
                                    GUINT_TO_POINTER(count + 1));
            }
            g_free(val);
            ctx->info->is_smb2 = TRUE;
        }

        /* ---- SMB1 Command (for stats) ---- */
        if (g_strcmp0(abbrev, "smb.cmd") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) {
                gpointer existing = g_hash_table_lookup(ctx->info->cmd_counts, val);
                guint count = existing ? GPOINTER_TO_UINT(existing) : 0;
                g_hash_table_insert(ctx->info->cmd_counts, g_strdup(val),
                                    GUINT_TO_POINTER(count + 1));
            }
            g_free(val);
        }

        /* ---- SMB2 Tree / Share path ---- */
        if (g_strcmp0(abbrev, "smb2.tree") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            add_unique_string(&ctx->info->tree_paths, val);
            g_free(val);
        }

        /* ---- SMB2 Filename (capped) ---- */
        if (g_strcmp0(abbrev, "smb2.filename") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            ctx->info->filename_total++;
            if (val && *val && g_list_length(ctx->info->filenames) < 100) {
                add_unique_string(&ctx->info->filenames, val);
            }
            g_free(val);
        }

        /* ---- SMB2 Session Setup fields ---- */
        if (g_strcmp0(abbrev, "smb2.acct") == 0 && !ctx->info->auth_username) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) ctx->info->auth_username = val;
            else g_free(val);
        }
        if (g_strcmp0(abbrev, "smb2.domain") == 0 && !ctx->info->auth_domain) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) ctx->info->auth_domain = val;
            else g_free(val);
        }
        if (g_strcmp0(abbrev, "smb2.host") == 0 && !ctx->info->auth_hostname) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) ctx->info->auth_hostname = val;
            else g_free(val);
        }

        /* ---- SMB1 Native OS / LAN Manager ---- */
        if (g_strcmp0(abbrev, "smb.native_os") == 0 && !ctx->info->native_os) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) ctx->info->native_os = val;
            else g_free(val);
        }
        if (g_strcmp0(abbrev, "smb.native_lanman") == 0 && !ctx->info->native_lanman) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) ctx->info->native_lanman = val;
            else g_free(val);
        }

        /* ---- NTLMSSP Authentication fields ---- */
        if (g_strcmp0(abbrev, "ntlmssp.auth.domain") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) {
                g_free(ctx->info->auth_domain);
                ctx->info->auth_domain = val;
            } else {
                g_free(val);
            }
        }
        if (g_strcmp0(abbrev, "ntlmssp.auth.username") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) {
                g_free(ctx->info->auth_username);
                ctx->info->auth_username = val;
            } else {
                g_free(val);
            }
        }
        if (g_strcmp0(abbrev, "ntlmssp.auth.hostname") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) {
                g_free(ctx->info->auth_hostname);
                ctx->info->auth_hostname = val;
            } else {
                g_free(val);
            }
        }
        if (g_strcmp0(abbrev, "ntlmssp.challenge.target_name") == 0 && !ctx->info->target_name) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) ctx->info->target_name = val;
            else g_free(val);
        }

        /* ---- DCE/RPC Bind Interface UUID ---- */
        if (g_strcmp0(abbrev, "dcerpc.cn_bind_to_uuid") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            add_unique_string(&ctx->info->dcerpc_interfaces, val);
            g_free(val);
        }

        /* ---- DCE/RPC Secondary Address (named pipe) ---- */
        if (g_strcmp0(abbrev, "dcerpc.cn_sec_addr") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            add_unique_string(&ctx->info->named_pipes, val);
            g_free(val);
        }
    }

    /* Recurse into children */
    for (proto_node *child = node->first_child; child; child = child->next) {
        walk_smb_proto_tree(child, ctx, depth + 1);
    }
}

smb_info_t* packet_analyzer_extract_smb_info(capture_file *cf,
                                             const gchar *addr_a,
                                             const gchar *addr_b,
                                             guint16 port,
                                             gboolean addr_is_mac)
{
    smb_info_t *info = g_new0(smb_info_t, 1);
    info->cmd_counts = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);

    if (!cf || cf->state != FILE_READ_DONE || !cf->provider.frames || cf->count == 0) {
        return info;
    }

    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING,
           "SMB analysis: addr_a=%s, addr_b=%s, port=%u, is_mac=%d",
           addr_a ? addr_a : "(null)", addr_b ? addr_b : "(null)",
           port, addr_is_mac);

    smb_walk_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.info = info;

    epan_dissect_t *edt = epan_dissect_new(cf->epan, TRUE, TRUE);

    guint32 matched = 0;
    for (guint32 framenum = 1; framenum <= cf->count; framenum++) {
        frame_data *fdata = frame_data_sequence_find(cf->provider.frames, framenum);
        if (!fdata || fdata->file_off < 0)
            continue;

        int err = 0;
        gchar *err_info_str = NULL;
        wtap_rec rec;
        gboolean read_ok;

#if VERSION_MINOR >= 6
        wtap_rec_init(&rec, fdata->cap_len);
        read_ok = wtap_seek_read(cf->provider.wth, fdata->file_off, &rec, &err, &err_info_str);
        if (read_ok) {
            int fts = wtap_file_type_subtype(cf->provider.wth);
            epan_dissect_run(edt, fts, &rec, fdata, NULL);
#else
        {
            Buffer buf;
            ws_buffer_init(&buf, fdata->cap_len);
            wtap_rec_init(&rec);
            read_ok = wtap_seek_read(cf->provider.wth, fdata->file_off, &rec, &buf, &err, &err_info_str);
            if (read_ok) {
                int fts = wtap_file_type_subtype(cf->provider.wth);
                tvbuff_t *tvb = tvb_new_real_data(ws_buffer_start_ptr(&buf),
                                                  rec.rec_header.packet_header.caplen,
                                                  rec.rec_header.packet_header.len);
                epan_dissect_run(edt, fts, &rec, tvb, fdata, NULL);
#endif
                /* Match addresses and port */
                {
                    gchar pkt_src[MAX_ADDR_STR_LEN], pkt_dst[MAX_ADDR_STR_LEN];
                    if (addr_is_mac) {
                        address_to_str_buf(&edt->pi.dl_src, pkt_src, sizeof(pkt_src));
                        address_to_str_buf(&edt->pi.dl_dst, pkt_dst, sizeof(pkt_dst));
                    } else {
                        address_to_str_buf(&edt->pi.net_src, pkt_src, sizeof(pkt_src));
                        address_to_str_buf(&edt->pi.net_dst, pkt_dst, sizeof(pkt_dst));
                    }
                    gboolean addr_ok =
                        (g_strcmp0(pkt_src, addr_a) == 0 && g_strcmp0(pkt_dst, addr_b) == 0) ||
                        (g_strcmp0(pkt_src, addr_b) == 0 && g_strcmp0(pkt_dst, addr_a) == 0);
                    gboolean port_ok =
                        ((guint32)port == edt->pi.srcport || (guint32)port == edt->pi.destport);

                    if (addr_ok && port_ok) {
                        matched++;
                        walk_smb_proto_tree(edt->tree, &ctx, 0);
                    }
                }

                epan_dissect_reset(edt);
#if VERSION_MINOR >= 6
        }
        wtap_rec_cleanup(&rec);
#else
            }
            wtap_rec_cleanup(&rec);
            ws_buffer_free(&buf);
        }
#endif
        if (err_info_str) {
            g_free(err_info_str);
        }

        if (matched % 50 == 0)
            circle_vis_pump_events();
    }

    epan_dissect_free(edt);

    info->matched_packets = matched;
    info->found = (matched > 0);

    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING,
           "SMB analysis done: %u packets matched, found=%d, smb2=%d, "
           "dialect=%s, user=%s, trees=%u, files=%u, pipes=%u, dcerpc=%u",
           matched, info->found, info->is_smb2,
           info->dialect ? info->dialect : "(none)",
           info->auth_username ? info->auth_username : "(none)",
           info->tree_paths ? g_list_length(info->tree_paths) : 0,
           info->filenames ? g_list_length(info->filenames) : 0,
           info->named_pipes ? g_list_length(info->named_pipes) : 0,
           info->dcerpc_interfaces ? g_list_length(info->dcerpc_interfaces) : 0);

    return info;
}

/* ------------------------------------------------------------------ */
/* Kerberos Information Extraction                                      */
/* ------------------------------------------------------------------ */

void packet_analyzer_free_kerberos_info(kerberos_info_t *info)
{
    if (!info) return;
    g_free(info->realm);
    g_free(info->client_realm);
    if (info->client_names)      g_list_free_full(info->client_names, g_free);
    if (info->service_names)     g_list_free_full(info->service_names, g_free);
    if (info->encryption_types)  g_list_free_full(info->encryption_types, g_free);
    if (info->msg_type_counts)   g_hash_table_destroy(info->msg_type_counts);
    if (info->error_counts)      g_hash_table_destroy(info->error_counts);
    if (info->error_texts)       g_list_free_full(info->error_texts, g_free);
    g_free(info);
}

/* Context for the Kerberos proto-tree walker */
typedef struct {
    kerberos_info_t *info;
} krb_walk_ctx_t;

/* Recursive proto-tree walker that collects Kerberos fields. */
static void walk_kerberos_proto_tree(proto_node *node, krb_walk_ctx_t *ctx, int depth)
{
    if (!node || depth > 60) return;

    field_info *fi = node->finfo;
    if (fi && fi->hfinfo && fi->hfinfo->abbrev) {
        const gchar *abbrev = fi->hfinfo->abbrev;
        gchar label[ITEM_LABEL_LENGTH];
        label[0] = '\0';

        /* ---- Message Type (for stats) ---- */
        if (g_strcmp0(abbrev, "kerberos.msg_type") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) {
                gpointer existing = g_hash_table_lookup(ctx->info->msg_type_counts, val);
                guint count = existing ? GPOINTER_TO_UINT(existing) : 0;
                g_hash_table_insert(ctx->info->msg_type_counts, g_strdup(val),
                                    GUINT_TO_POINTER(count + 1));
            }
            g_free(val);
        }

        /* ---- Client Principal Name ---- */
        if (g_strcmp0(abbrev, "kerberos.CNameString") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            add_unique_string(&ctx->info->client_names, val);
            g_free(val);
        }

        /* ---- Service Principal Name ---- */
        if (g_strcmp0(abbrev, "kerberos.SNameString") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            add_unique_string(&ctx->info->service_names, val);
            g_free(val);
        }

        /* ---- Realm ---- */
        if (g_strcmp0(abbrev, "kerberos.realm") == 0 && !ctx->info->realm) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) ctx->info->realm = val;
            else g_free(val);
        }

        /* ---- Client Realm ---- */
        if (g_strcmp0(abbrev, "kerberos.crealm") == 0 && !ctx->info->client_realm) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) ctx->info->client_realm = val;
            else g_free(val);
        }

        /* ---- Encryption Type ---- */
        if (g_strcmp0(abbrev, "kerberos.etype") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            add_unique_string(&ctx->info->encryption_types, val);
            g_free(val);
        }

        /* ---- Error Code (for stats) ---- */
        if (g_strcmp0(abbrev, "kerberos.error_code") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) {
                gpointer existing = g_hash_table_lookup(ctx->info->error_counts, val);
                guint count = existing ? GPOINTER_TO_UINT(existing) : 0;
                g_hash_table_insert(ctx->info->error_counts, g_strdup(val),
                                    GUINT_TO_POINTER(count + 1));
            }
            g_free(val);
        }

        /* ---- Error Text ---- */
        if (g_strcmp0(abbrev, "kerberos.e_text") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            add_unique_string(&ctx->info->error_texts, val);
            g_free(val);
        }
    }

    /* Recurse into children */
    for (proto_node *child = node->first_child; child; child = child->next) {
        walk_kerberos_proto_tree(child, ctx, depth + 1);
    }
}

kerberos_info_t* packet_analyzer_extract_kerberos_info(capture_file *cf,
                                                      const gchar *addr_a,
                                                      const gchar *addr_b,
                                                      guint16 port,
                                                      gboolean addr_is_mac)
{
    kerberos_info_t *info = g_new0(kerberos_info_t, 1);
    info->msg_type_counts = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
    info->error_counts    = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);

    if (!cf || cf->state != FILE_READ_DONE || !cf->provider.frames || cf->count == 0) {
        return info;
    }

    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING,
           "Kerberos analysis: addr_a=%s, addr_b=%s, port=%u, is_mac=%d",
           addr_a ? addr_a : "(null)", addr_b ? addr_b : "(null)",
           port, addr_is_mac);

    krb_walk_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.info = info;

    epan_dissect_t *edt = epan_dissect_new(cf->epan, TRUE, TRUE);

    guint32 matched = 0;
    for (guint32 framenum = 1; framenum <= cf->count; framenum++) {
        frame_data *fdata = frame_data_sequence_find(cf->provider.frames, framenum);
        if (!fdata || fdata->file_off < 0)
            continue;

        int err = 0;
        gchar *err_info_str = NULL;
        wtap_rec rec;
        gboolean read_ok;

#if VERSION_MINOR >= 6
        wtap_rec_init(&rec, fdata->cap_len);
        read_ok = wtap_seek_read(cf->provider.wth, fdata->file_off, &rec, &err, &err_info_str);
        if (read_ok) {
            int fts = wtap_file_type_subtype(cf->provider.wth);
            epan_dissect_run(edt, fts, &rec, fdata, NULL);
#else
        {
            Buffer buf;
            ws_buffer_init(&buf, fdata->cap_len);
            wtap_rec_init(&rec);
            read_ok = wtap_seek_read(cf->provider.wth, fdata->file_off, &rec, &buf, &err, &err_info_str);
            if (read_ok) {
                int fts = wtap_file_type_subtype(cf->provider.wth);
                tvbuff_t *tvb = tvb_new_real_data(ws_buffer_start_ptr(&buf),
                                                  rec.rec_header.packet_header.caplen,
                                                  rec.rec_header.packet_header.len);
                epan_dissect_run(edt, fts, &rec, tvb, fdata, NULL);
#endif
                /* Match addresses and port */
                {
                    gchar pkt_src[MAX_ADDR_STR_LEN], pkt_dst[MAX_ADDR_STR_LEN];
                    if (addr_is_mac) {
                        address_to_str_buf(&edt->pi.dl_src, pkt_src, sizeof(pkt_src));
                        address_to_str_buf(&edt->pi.dl_dst, pkt_dst, sizeof(pkt_dst));
                    } else {
                        address_to_str_buf(&edt->pi.net_src, pkt_src, sizeof(pkt_src));
                        address_to_str_buf(&edt->pi.net_dst, pkt_dst, sizeof(pkt_dst));
                    }
                    gboolean addr_ok =
                        (g_strcmp0(pkt_src, addr_a) == 0 && g_strcmp0(pkt_dst, addr_b) == 0) ||
                        (g_strcmp0(pkt_src, addr_b) == 0 && g_strcmp0(pkt_dst, addr_a) == 0);
                    gboolean port_ok =
                        ((guint32)port == edt->pi.srcport || (guint32)port == edt->pi.destport);

                    if (addr_ok && port_ok) {
                        matched++;
                        walk_kerberos_proto_tree(edt->tree, &ctx, 0);
                    }
                }

                epan_dissect_reset(edt);
#if VERSION_MINOR >= 6
        }
        wtap_rec_cleanup(&rec);
#else
            }
            wtap_rec_cleanup(&rec);
            ws_buffer_free(&buf);
        }
#endif
        if (err_info_str) {
            g_free(err_info_str);
        }

        if (matched % 50 == 0)
            circle_vis_pump_events();
    }

    epan_dissect_free(edt);

    info->matched_packets = matched;
    info->found = (matched > 0);

    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING,
           "Kerberos analysis done: %u packets matched, found=%d, "
           "realm=%s, clients=%u, services=%u, etypes=%u, errors=%u",
           matched, info->found,
           info->realm ? info->realm : "(none)",
           info->client_names ? g_list_length(info->client_names) : 0,
           info->service_names ? g_list_length(info->service_names) : 0,
           info->encryption_types ? g_list_length(info->encryption_types) : 0,
           info->error_counts ? g_hash_table_size(info->error_counts) : 0);

    return info;
}

/* ------------------------------------------------------------------ */
/* Email Protocol Information Extraction (SMTP / IMAP / POP3 + IMF)     */
/* ------------------------------------------------------------------ */

void packet_analyzer_free_email_info(email_info_t *info)
{
    if (!info) return;
    g_free(info->auth_username);
    if (info->mail_from)       g_list_free_full(info->mail_from, g_free);
    if (info->rcpt_to)         g_list_free_full(info->rcpt_to, g_free);
    if (info->ehlo_domains)    g_list_free_full(info->ehlo_domains, g_free);
    if (info->folders)         g_list_free_full(info->folders, g_free);
    if (info->subjects)        g_list_free_full(info->subjects, g_free);
    if (info->from_addrs)      g_list_free_full(info->from_addrs, g_free);
    if (info->to_addrs)        g_list_free_full(info->to_addrs, g_free);
    if (info->user_agents)     g_list_free_full(info->user_agents, g_free);
    if (info->content_types)   g_list_free_full(info->content_types, g_free);
    if (info->cmd_counts)      g_hash_table_destroy(info->cmd_counts);
    if (info->response_counts) g_hash_table_destroy(info->response_counts);
    g_free(info);
}

/* Context for the email proto-tree walker */
typedef struct {
    email_info_t *info;
    gchar *last_smtp_cmd;   /* Last seen smtp.req.command value (owned) */
    gchar *last_pop_cmd;    /* Last seen pop.request.command value (owned) */
} email_walk_ctx_t;

/* Helper: increment a count in a string→count hash table */
static void increment_hash_count(GHashTable *ht, const gchar *key)
{
    if (!key || !*key) return;
    gpointer existing = g_hash_table_lookup(ht, key);
    guint count = existing ? GPOINTER_TO_UINT(existing) : 0;
    g_hash_table_insert(ht, g_strdup(key), GUINT_TO_POINTER(count + 1));
}

/* Recursive proto-tree walker that collects SMTP, IMAP, POP3, and IMF fields. */
static void walk_email_proto_tree(proto_node *node, email_walk_ctx_t *ctx, int depth)
{
    if (!node || depth > 60) return;

    field_info *fi = node->finfo;
    if (fi && fi->hfinfo && fi->hfinfo->abbrev) {
        const gchar *abbrev = fi->hfinfo->abbrev;
        gchar label[ITEM_LABEL_LENGTH];
        label[0] = '\0';

        /* =============== SMTP fields =============== */

        /* SMTP Command */
        if (g_strcmp0(abbrev, "smtp.req.command") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) {
                increment_hash_count(ctx->info->cmd_counts, val);
                /* Save for parameter context */
                g_free(ctx->last_smtp_cmd);
                ctx->last_smtp_cmd = g_strdup(val);
            }
            g_free(val);
        }

        /* SMTP Request Parameter — interpret based on current command */
        if (g_strcmp0(abbrev, "smtp.req.parameter") == 0 && ctx->last_smtp_cmd) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) {
                if (g_ascii_strcasecmp(ctx->last_smtp_cmd, "MAIL") == 0) {
                    add_unique_string(&ctx->info->mail_from, val);
                } else if (g_ascii_strcasecmp(ctx->last_smtp_cmd, "RCPT") == 0) {
                    add_unique_string(&ctx->info->rcpt_to, val);
                } else if (g_ascii_strcasecmp(ctx->last_smtp_cmd, "EHLO") == 0 ||
                           g_ascii_strcasecmp(ctx->last_smtp_cmd, "HELO") == 0) {
                    add_unique_string(&ctx->info->ehlo_domains, val);
                }
            }
            g_free(val);
        }

        /* SMTP Response Code */
        if (g_strcmp0(abbrev, "smtp.response.code") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) {
                increment_hash_count(ctx->info->response_counts, val);
            }
            g_free(val);
        }

        /* SMTP AUTH Username */
        if (g_strcmp0(abbrev, "smtp.auth.username") == 0 && !ctx->info->auth_username) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) ctx->info->auth_username = val;
            else g_free(val);
        }

        /* =============== IMAP fields =============== */

        /* IMAP Request Command */
        if (g_strcmp0(abbrev, "imap.request.command") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) {
                increment_hash_count(ctx->info->cmd_counts, val);
            }
            g_free(val);
        }

        /* IMAP Response Status */
        if (g_strcmp0(abbrev, "imap.response.status") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) {
                increment_hash_count(ctx->info->response_counts, val);
            }
            g_free(val);
        }

        /* IMAP Folder */
        if (g_strcmp0(abbrev, "imap.request.folder") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            add_unique_string(&ctx->info->folders, val);
            g_free(val);
        }

        /* IMAP Username */
        if (g_strcmp0(abbrev, "imap.request.username") == 0 && !ctx->info->auth_username) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) ctx->info->auth_username = val;
            else g_free(val);
        }

        /* =============== POP3 fields =============== */

        /* POP Request Command */
        if (g_strcmp0(abbrev, "pop.request.command") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) {
                increment_hash_count(ctx->info->cmd_counts, val);
                g_free(ctx->last_pop_cmd);
                ctx->last_pop_cmd = g_strdup(val);
            }
            g_free(val);
        }

        /* POP Request Parameter — extract username from USER command */
        if (g_strcmp0(abbrev, "pop.request.parameter") == 0 && ctx->last_pop_cmd) {
            if (g_ascii_strcasecmp(ctx->last_pop_cmd, "USER") == 0 &&
                !ctx->info->auth_username) {
                fill_label_compat(fi, label);
                gchar *val = label_value(label);
                if (val && *val) ctx->info->auth_username = val;
                else g_free(val);
            }
        }

        /* POP Response Indicator */
        if (g_strcmp0(abbrev, "pop.response.indicator") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) {
                increment_hash_count(ctx->info->response_counts, val);
            }
            g_free(val);
        }

        /* =============== IMF (email header) fields =============== */

        if (g_strcmp0(abbrev, "imf.from") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            add_unique_string(&ctx->info->from_addrs, val);
            g_free(val);
        }
        if (g_strcmp0(abbrev, "imf.to") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            add_unique_string(&ctx->info->to_addrs, val);
            g_free(val);
        }
        if (g_strcmp0(abbrev, "imf.subject") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val && g_list_length(ctx->info->subjects) < 50) {
                add_unique_string(&ctx->info->subjects, val);
            }
            g_free(val);
        }
        if (g_strcmp0(abbrev, "imf.user_agent") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            add_unique_string(&ctx->info->user_agents, val);
            g_free(val);
        }
        if (g_strcmp0(abbrev, "imf.content.type") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            add_unique_string(&ctx->info->content_types, val);
            g_free(val);
        }
    }

    /* Recurse into children */
    for (proto_node *child = node->first_child; child; child = child->next) {
        walk_email_proto_tree(child, ctx, depth + 1);
    }
}

email_info_t* packet_analyzer_extract_email_info(capture_file *cf,
                                                const gchar *addr_a,
                                                const gchar *addr_b,
                                                guint16 port,
                                                gboolean addr_is_mac)
{
    email_info_t *info = g_new0(email_info_t, 1);
    info->cmd_counts      = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
    info->response_counts = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);

    if (!cf || cf->state != FILE_READ_DONE || !cf->provider.frames || cf->count == 0) {
        return info;
    }

    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING,
           "Email analysis: addr_a=%s, addr_b=%s, port=%u, is_mac=%d",
           addr_a ? addr_a : "(null)", addr_b ? addr_b : "(null)",
           port, addr_is_mac);

    email_walk_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.info = info;

    epan_dissect_t *edt = epan_dissect_new(cf->epan, TRUE, TRUE);

    guint32 matched = 0;
    for (guint32 framenum = 1; framenum <= cf->count; framenum++) {
        frame_data *fdata = frame_data_sequence_find(cf->provider.frames, framenum);
        if (!fdata || fdata->file_off < 0)
            continue;

        int err = 0;
        gchar *err_info_str = NULL;
        wtap_rec rec;
        gboolean read_ok;

#if VERSION_MINOR >= 6
        wtap_rec_init(&rec, fdata->cap_len);
        read_ok = wtap_seek_read(cf->provider.wth, fdata->file_off, &rec, &err, &err_info_str);
        if (read_ok) {
            int fts = wtap_file_type_subtype(cf->provider.wth);
            epan_dissect_run(edt, fts, &rec, fdata, NULL);
#else
        {
            Buffer buf;
            ws_buffer_init(&buf, fdata->cap_len);
            wtap_rec_init(&rec);
            read_ok = wtap_seek_read(cf->provider.wth, fdata->file_off, &rec, &buf, &err, &err_info_str);
            if (read_ok) {
                int fts = wtap_file_type_subtype(cf->provider.wth);
                tvbuff_t *tvb = tvb_new_real_data(ws_buffer_start_ptr(&buf),
                                                  rec.rec_header.packet_header.caplen,
                                                  rec.rec_header.packet_header.len);
                epan_dissect_run(edt, fts, &rec, tvb, fdata, NULL);
#endif
                /* Match addresses and port */
                {
                    gchar pkt_src[MAX_ADDR_STR_LEN], pkt_dst[MAX_ADDR_STR_LEN];
                    if (addr_is_mac) {
                        address_to_str_buf(&edt->pi.dl_src, pkt_src, sizeof(pkt_src));
                        address_to_str_buf(&edt->pi.dl_dst, pkt_dst, sizeof(pkt_dst));
                    } else {
                        address_to_str_buf(&edt->pi.net_src, pkt_src, sizeof(pkt_src));
                        address_to_str_buf(&edt->pi.net_dst, pkt_dst, sizeof(pkt_dst));
                    }
                    gboolean addr_ok =
                        (g_strcmp0(pkt_src, addr_a) == 0 && g_strcmp0(pkt_dst, addr_b) == 0) ||
                        (g_strcmp0(pkt_src, addr_b) == 0 && g_strcmp0(pkt_dst, addr_a) == 0);
                    gboolean port_ok =
                        ((guint32)port == edt->pi.srcport || (guint32)port == edt->pi.destport);

                    if (addr_ok && port_ok) {
                        matched++;
                        /* Reset per-frame command state */
                        g_free(ctx.last_smtp_cmd);
                        ctx.last_smtp_cmd = NULL;
                        g_free(ctx.last_pop_cmd);
                        ctx.last_pop_cmd = NULL;
                        walk_email_proto_tree(edt->tree, &ctx, 0);
                    }
                }

                epan_dissect_reset(edt);
#if VERSION_MINOR >= 6
        }
        wtap_rec_cleanup(&rec);
#else
            }
            wtap_rec_cleanup(&rec);
            ws_buffer_free(&buf);
        }
#endif
        if (err_info_str) {
            g_free(err_info_str);
        }

        if (matched % 50 == 0)
            circle_vis_pump_events();
    }

    /* Clean up per-frame state */
    g_free(ctx.last_smtp_cmd);
    g_free(ctx.last_pop_cmd);

    epan_dissect_free(edt);

    info->matched_packets = matched;
    info->found = (matched > 0);

    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING,
           "Email analysis done: %u packets matched, found=%d, "
           "user=%s, cmds=%u, responses=%u, subjects=%u",
           matched, info->found,
           info->auth_username ? info->auth_username : "(none)",
           info->cmd_counts ? g_hash_table_size(info->cmd_counts) : 0,
           info->response_counts ? g_hash_table_size(info->response_counts) : 0,
           info->subjects ? g_list_length(info->subjects) : 0);

    return info;
}

/* ------------------------------------------------------------------ */
/* SQL Database Information Extraction (MSSQL/TDS, MySQL, PostgreSQL)    */
/* ------------------------------------------------------------------ */

void packet_analyzer_free_sql_info(sql_info_t *info)
{
    if (!info) return;
    g_free(info->db_type);
    g_free(info->version);
    g_free(info->username);
    g_free(info->database);
    g_free(info->server_name);
    g_free(info->app_name);
    g_free(info->client_name);
    g_free(info->auth_plugin);
    if (info->queries)          g_list_free_full(info->queries, g_free);
    if (info->error_messages)   g_list_free_full(info->error_messages, g_free);
    if (info->pg_params)        g_hash_table_destroy(info->pg_params);
    if (info->cmd_counts)       g_hash_table_destroy(info->cmd_counts);
    if (info->response_counts)  g_hash_table_destroy(info->response_counts);
    g_free(info);
}

/* Context for the SQL proto-tree walker */
typedef struct {
    sql_info_t *info;
    gchar *last_pg_param_name;  /* PostgreSQL: last seen parameter_name (owned) */
} sql_walk_ctx_t;

/* Recursive proto-tree walker that collects TDS / MySQL / PostgreSQL fields. */
static void walk_sql_proto_tree(proto_node *node, sql_walk_ctx_t *ctx, int depth)
{
    if (!node || depth > 60) return;

    field_info *fi = node->finfo;
    if (fi && fi->hfinfo && fi->hfinfo->abbrev) {
        const gchar *abbrev = fi->hfinfo->abbrev;
        gchar label[ITEM_LABEL_LENGTH];
        label[0] = '\0';

        /* =============== TDS / MSSQL fields =============== */

        /* TDS7 Login fields */
        if (g_strcmp0(abbrev, "tds.7login.username") == 0 && !ctx->info->username) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) { ctx->info->username = val; ctx->info->db_type = g_strdup("MSSQL"); }
            else g_free(val);
        }
        if (g_strcmp0(abbrev, "tds.7login.servername") == 0 && !ctx->info->server_name) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) ctx->info->server_name = val;
            else g_free(val);
        }
        if (g_strcmp0(abbrev, "tds.7login.appname") == 0 && !ctx->info->app_name) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) ctx->info->app_name = val;
            else g_free(val);
        }
        if (g_strcmp0(abbrev, "tds.7login.databasename") == 0 && !ctx->info->database) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) ctx->info->database = val;
            else g_free(val);
        }
        if (g_strcmp0(abbrev, "tds.7login.clientname") == 0 && !ctx->info->client_name) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) ctx->info->client_name = val;
            else g_free(val);
        }
        if (g_strcmp0(abbrev, "tds.7login.version") == 0 && !ctx->info->version) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) { ctx->info->version = val; ctx->info->db_type = g_strdup("MSSQL"); }
            else g_free(val);
        }

        /* TDS5 Login fields (Sybase) */
        if (g_strcmp0(abbrev, "tds.login.username") == 0 && !ctx->info->username) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) { ctx->info->username = val; if (!ctx->info->db_type) ctx->info->db_type = g_strdup("MSSQL"); }
            else g_free(val);
        }
        if (g_strcmp0(abbrev, "tds.login.servname") == 0 && !ctx->info->server_name) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) ctx->info->server_name = val;
            else g_free(val);
        }
        if (g_strcmp0(abbrev, "tds.login.appname") == 0 && !ctx->info->app_name) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) ctx->info->app_name = val;
            else g_free(val);
        }

        /* TDS Query */
        if (g_strcmp0(abbrev, "tds.query") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            ctx->info->query_total++;
            if (val && *val && g_list_length(ctx->info->queries) < 50) {
                add_unique_string(&ctx->info->queries, val);
            }
            g_free(val);
            if (!ctx->info->db_type) ctx->info->db_type = g_strdup("MSSQL");
        }

        /* TDS Language text (TDS5 queries) */
        if (g_strcmp0(abbrev, "tds.lang.language_text") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            ctx->info->query_total++;
            if (val && *val && g_list_length(ctx->info->queries) < 50) {
                add_unique_string(&ctx->info->queries, val);
            }
            g_free(val);
        }

        /* TDS RPC procedure name */
        if (g_strcmp0(abbrev, "tds.rpc.name") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) {
                gchar *rpc_label = g_strdup_printf("RPC: %s", val);
                increment_hash_count(ctx->info->cmd_counts, rpc_label);
                g_free(rpc_label);
            }
            g_free(val);
        }

        /* TDS Error message */
        if (g_strcmp0(abbrev, "tds.error.message") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val && g_list_length(ctx->info->error_messages) < 50) {
                add_unique_string(&ctx->info->error_messages, val);
            }
            g_free(val);
        }

        /* =============== MySQL / MariaDB fields =============== */

        if (g_strcmp0(abbrev, "mysql.version") == 0 && !ctx->info->version) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) {
                ctx->info->version = val;
                g_free(ctx->info->db_type);
                ctx->info->db_type = g_strdup("MySQL");
            } else g_free(val);
        }
        if (g_strcmp0(abbrev, "mysql.user") == 0 && !ctx->info->username) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) { ctx->info->username = val; if (!ctx->info->db_type) ctx->info->db_type = g_strdup("MySQL"); }
            else g_free(val);
        }
        if (g_strcmp0(abbrev, "mysql.schema") == 0 && !ctx->info->database) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) ctx->info->database = val;
            else g_free(val);
        }
        if (g_strcmp0(abbrev, "mysql.query") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            ctx->info->query_total++;
            if (val && *val && g_list_length(ctx->info->queries) < 50) {
                add_unique_string(&ctx->info->queries, val);
            }
            g_free(val);
            if (!ctx->info->db_type) ctx->info->db_type = g_strdup("MySQL");
        }
        if (g_strcmp0(abbrev, "mysql.command") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) increment_hash_count(ctx->info->cmd_counts, val);
            g_free(val);
        }
        if (g_strcmp0(abbrev, "mysql.response_code") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) increment_hash_count(ctx->info->response_counts, val);
            g_free(val);
        }
        if (g_strcmp0(abbrev, "mysql.error.message") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val && g_list_length(ctx->info->error_messages) < 50) {
                add_unique_string(&ctx->info->error_messages, val);
            }
            g_free(val);
        }
        if (g_strcmp0(abbrev, "mysql.client_auth_plugin") == 0 && !ctx->info->auth_plugin) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) ctx->info->auth_plugin = val;
            else g_free(val);
        }

        /* =============== PostgreSQL fields =============== */

        if (g_strcmp0(abbrev, "pgsql.query") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            ctx->info->query_total++;
            if (val && *val && g_list_length(ctx->info->queries) < 50) {
                add_unique_string(&ctx->info->queries, val);
            }
            g_free(val);
            if (!ctx->info->db_type) ctx->info->db_type = g_strdup("PostgreSQL");
        }
        if (g_strcmp0(abbrev, "pgsql.statement") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            ctx->info->query_total++;
            if (val && *val && g_list_length(ctx->info->queries) < 50) {
                add_unique_string(&ctx->info->queries, val);
            }
            g_free(val);
        }
        if (g_strcmp0(abbrev, "pgsql.authtype") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) {
                g_free(ctx->info->auth_plugin);
                ctx->info->auth_plugin = val;
                if (!ctx->info->db_type) ctx->info->db_type = g_strdup("PostgreSQL");
            } else g_free(val);
        }
        if (g_strcmp0(abbrev, "pgsql.parameter_name") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            g_free(ctx->last_pg_param_name);
            ctx->last_pg_param_name = (val && *val) ? g_strdup(val) : NULL;
            /* Check for special parameters */
            if (val && g_strcmp0(val, "server_version") == 0) {
                /* We'll capture the value in the next parameter_value field */
            }
            g_free(val);
            if (!ctx->info->db_type) ctx->info->db_type = g_strdup("PostgreSQL");
        }
        if (g_strcmp0(abbrev, "pgsql.parameter_value") == 0 && ctx->last_pg_param_name) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) {
                if (g_strcmp0(ctx->last_pg_param_name, "server_version") == 0 && !ctx->info->version) {
                    ctx->info->version = g_strdup(val);
                }
                if (g_strcmp0(ctx->last_pg_param_name, "application_name") == 0 && !ctx->info->app_name) {
                    ctx->info->app_name = g_strdup(val);
                }
                /* Store in pg_params hash */
                g_hash_table_insert(ctx->info->pg_params,
                                    g_strdup(ctx->last_pg_param_name),
                                    g_strdup(val));
            }
            g_free(val);
            g_free(ctx->last_pg_param_name);
            ctx->last_pg_param_name = NULL;
        }
        if (g_strcmp0(abbrev, "pgsql.severity") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) increment_hash_count(ctx->info->response_counts, val);
            g_free(val);
        }
        if (g_strcmp0(abbrev, "pgsql.message") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val && g_list_length(ctx->info->error_messages) < 50) {
                add_unique_string(&ctx->info->error_messages, val);
            }
            g_free(val);
        }
        if (g_strcmp0(abbrev, "pgsql.tag") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) increment_hash_count(ctx->info->cmd_counts, val);
            g_free(val);
        }
    }

    /* Recurse into children */
    for (proto_node *child = node->first_child; child; child = child->next) {
        walk_sql_proto_tree(child, ctx, depth + 1);
    }
}

sql_info_t* packet_analyzer_extract_sql_info(capture_file *cf,
                                             const gchar *addr_a,
                                             const gchar *addr_b,
                                             guint16 port,
                                             gboolean addr_is_mac)
{
    sql_info_t *info = g_new0(sql_info_t, 1);
    info->pg_params       = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
    info->cmd_counts      = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
    info->response_counts = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);

    if (!cf || cf->state != FILE_READ_DONE || !cf->provider.frames || cf->count == 0) {
        return info;
    }

    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING,
           "SQL analysis: addr_a=%s, addr_b=%s, port=%u, is_mac=%d",
           addr_a ? addr_a : "(null)", addr_b ? addr_b : "(null)",
           port, addr_is_mac);

    sql_walk_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.info = info;

    epan_dissect_t *edt = epan_dissect_new(cf->epan, TRUE, TRUE);

    guint32 matched = 0;
    for (guint32 framenum = 1; framenum <= cf->count; framenum++) {
        frame_data *fdata = frame_data_sequence_find(cf->provider.frames, framenum);
        if (!fdata || fdata->file_off < 0)
            continue;

        int err = 0;
        gchar *err_info_str = NULL;
        wtap_rec rec;
        gboolean read_ok;

#if VERSION_MINOR >= 6
        wtap_rec_init(&rec, fdata->cap_len);
        read_ok = wtap_seek_read(cf->provider.wth, fdata->file_off, &rec, &err, &err_info_str);
        if (read_ok) {
            int fts = wtap_file_type_subtype(cf->provider.wth);
            epan_dissect_run(edt, fts, &rec, fdata, NULL);
#else
        {
            Buffer buf;
            ws_buffer_init(&buf, fdata->cap_len);
            wtap_rec_init(&rec);
            read_ok = wtap_seek_read(cf->provider.wth, fdata->file_off, &rec, &buf, &err, &err_info_str);
            if (read_ok) {
                int fts = wtap_file_type_subtype(cf->provider.wth);
                tvbuff_t *tvb = tvb_new_real_data(ws_buffer_start_ptr(&buf),
                                                  rec.rec_header.packet_header.caplen,
                                                  rec.rec_header.packet_header.len);
                epan_dissect_run(edt, fts, &rec, tvb, fdata, NULL);
#endif
                /* Match addresses and port */
                {
                    gchar pkt_src[MAX_ADDR_STR_LEN], pkt_dst[MAX_ADDR_STR_LEN];
                    if (addr_is_mac) {
                        address_to_str_buf(&edt->pi.dl_src, pkt_src, sizeof(pkt_src));
                        address_to_str_buf(&edt->pi.dl_dst, pkt_dst, sizeof(pkt_dst));
                    } else {
                        address_to_str_buf(&edt->pi.net_src, pkt_src, sizeof(pkt_src));
                        address_to_str_buf(&edt->pi.net_dst, pkt_dst, sizeof(pkt_dst));
                    }
                    gboolean addr_ok =
                        (g_strcmp0(pkt_src, addr_a) == 0 && g_strcmp0(pkt_dst, addr_b) == 0) ||
                        (g_strcmp0(pkt_src, addr_b) == 0 && g_strcmp0(pkt_dst, addr_a) == 0);
                    gboolean port_ok =
                        ((guint32)port == edt->pi.srcport || (guint32)port == edt->pi.destport);

                    if (addr_ok && port_ok) {
                        matched++;
                        g_free(ctx.last_pg_param_name);
                        ctx.last_pg_param_name = NULL;
                        walk_sql_proto_tree(edt->tree, &ctx, 0);
                    }
                }

                epan_dissect_reset(edt);
#if VERSION_MINOR >= 6
        }
        wtap_rec_cleanup(&rec);
#else
            }
            wtap_rec_cleanup(&rec);
            ws_buffer_free(&buf);
        }
#endif
        if (err_info_str) {
            g_free(err_info_str);
        }

        if (matched % 50 == 0)
            circle_vis_pump_events();
    }

    g_free(ctx.last_pg_param_name);
    epan_dissect_free(edt);

    info->matched_packets = matched;
    info->found = (matched > 0);

    /* Default db_type based on port if not detected from fields */
    if (!info->db_type && info->found) {
        if (port == 1433)      info->db_type = g_strdup("MSSQL");
        else if (port == 3306) info->db_type = g_strdup("MySQL");
        else if (port == 5432) info->db_type = g_strdup("PostgreSQL");
    }

    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING,
           "SQL analysis done: %u packets matched, found=%d, "
           "type=%s, version=%s, user=%s, db=%s, queries=%u",
           matched, info->found,
           info->db_type ? info->db_type : "(none)",
           info->version ? info->version : "(none)",
           info->username ? info->username : "(none)",
           info->database ? info->database : "(none)",
           info->query_total);

    return info;
}

/* ------------------------------------------------------------------ */
/* VoIP Information Extraction (SIP / RTP / H.223)                      */
/* ------------------------------------------------------------------ */

void packet_analyzer_free_voip_info(voip_info_t *info)
{
    if (!info) return;
    if (info->call_ids)          g_list_free_full(info->call_ids, g_free);
    if (info->from_addrs)        g_list_free_full(info->from_addrs, g_free);
    if (info->to_addrs)          g_list_free_full(info->to_addrs, g_free);
    if (info->user_agents)       g_list_free_full(info->user_agents, g_free);
    if (info->content_types)     g_list_free_full(info->content_types, g_free);
    g_free(info->auth_username);
    if (info->method_counts)     g_hash_table_destroy(info->method_counts);
    if (info->status_counts)     g_hash_table_destroy(info->status_counts);
    if (info->rtp_ssrcs)         g_list_free_full(info->rtp_ssrcs, g_free);
    if (info->rtp_payload_types) g_list_free_full(info->rtp_payload_types, g_free);
    if (info->rtp_setup_methods) g_list_free_full(info->rtp_setup_methods, g_free);
    g_free(info);
}

/* Context for the VoIP proto-tree walker */
typedef struct {
    voip_info_t *info;
} voip_walk_ctx_t;

/* Recursive proto-tree walker that collects SIP / RTP / H.223 fields. */
static void walk_voip_proto_tree(proto_node *node, voip_walk_ctx_t *ctx, int depth)
{
    if (!node || depth > 60) return;

    field_info *fi = node->finfo;
    if (fi && fi->hfinfo && fi->hfinfo->abbrev) {
        const gchar *abbrev = fi->hfinfo->abbrev;
        gchar label[ITEM_LABEL_LENGTH];
        label[0] = '\0';

        /* =============== SIP fields =============== */

        /* SIP Method (request line) */
        if (g_strcmp0(abbrev, "sip.Method") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) increment_hash_count(ctx->info->method_counts, val);
            g_free(val);
        }

        /* SIP CSeq Method (also useful for counting methods on responses) */
        if (g_strcmp0(abbrev, "sip.CSeq.method") == 0) {
            /* We already count from sip.Method, skip duplicate counting */
        }

        /* SIP Status-Code */
        if (g_strcmp0(abbrev, "sip.Status-Code") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) increment_hash_count(ctx->info->status_counts, val);
            g_free(val);
        }

        /* SIP Call-ID */
        if (g_strcmp0(abbrev, "sip.Call-ID") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val && g_list_length(ctx->info->call_ids) < 100) {
                add_unique_string(&ctx->info->call_ids, val);
            }
            g_free(val);
        }

        /* SIP From address */
        if (g_strcmp0(abbrev, "sip.from.addr") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            add_unique_string(&ctx->info->from_addrs, val);
            g_free(val);
        }

        /* SIP To address */
        if (g_strcmp0(abbrev, "sip.to.addr") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            add_unique_string(&ctx->info->to_addrs, val);
            g_free(val);
        }

        /* SIP User-Agent */
        if (g_strcmp0(abbrev, "sip.User-Agent") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            add_unique_string(&ctx->info->user_agents, val);
            g_free(val);
        }

        /* SIP Content-Type */
        if (g_strcmp0(abbrev, "sip.Content-Type") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            add_unique_string(&ctx->info->content_types, val);
            g_free(val);
        }

        /* SIP auth username */
        if (g_strcmp0(abbrev, "sip.auth.username") == 0 && !ctx->info->auth_username) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) ctx->info->auth_username = val;
            else g_free(val);
        }

        /* =============== RTP fields =============== */

        /* RTP Payload Type */
        if (g_strcmp0(abbrev, "rtp.p_type") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            add_unique_string(&ctx->info->rtp_payload_types, val);
            g_free(val);
            ctx->info->rtp_packet_count++;
        }

        /* RTP SSRC */
        if (g_strcmp0(abbrev, "rtp.ssrc") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val && g_list_length(ctx->info->rtp_ssrcs) < 100) {
                add_unique_string(&ctx->info->rtp_ssrcs, val);
            }
            g_free(val);
        }

        /* RTP Setup Method */
        if (g_strcmp0(abbrev, "rtp.setup-method") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            add_unique_string(&ctx->info->rtp_setup_methods, val);
            g_free(val);
        }

        /* =============== H.223 fields =============== */

        if (g_strcmp0(abbrev, "h223.mux") == 0) {
            ctx->info->h223_mux_count++;
        }
    }

    /* Recurse into children */
    for (proto_node *child = node->first_child; child; child = child->next) {
        walk_voip_proto_tree(child, ctx, depth + 1);
    }
}

voip_info_t* packet_analyzer_extract_voip_info(capture_file *cf,
                                               const gchar *addr_a,
                                               const gchar *addr_b,
                                               guint16 port,
                                               gboolean addr_is_mac)
{
    voip_info_t *info = g_new0(voip_info_t, 1);
    info->method_counts = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
    info->status_counts = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);

    if (!cf || cf->state != FILE_READ_DONE || !cf->provider.frames || cf->count == 0) {
        return info;
    }

    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING,
           "VoIP analysis: addr_a=%s, addr_b=%s, port=%u, is_mac=%d",
           addr_a ? addr_a : "(null)", addr_b ? addr_b : "(null)",
           port, addr_is_mac);

    voip_walk_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.info = info;

    epan_dissect_t *edt = epan_dissect_new(cf->epan, TRUE, TRUE);

    guint32 matched = 0;
    for (guint32 framenum = 1; framenum <= cf->count; framenum++) {
        frame_data *fdata = frame_data_sequence_find(cf->provider.frames, framenum);
        if (!fdata || fdata->file_off < 0)
            continue;

        int err = 0;
        gchar *err_info_str = NULL;
        wtap_rec rec;
        gboolean read_ok;

#if VERSION_MINOR >= 6
        wtap_rec_init(&rec, fdata->cap_len);
        read_ok = wtap_seek_read(cf->provider.wth, fdata->file_off, &rec, &err, &err_info_str);
        if (read_ok) {
            int fts = wtap_file_type_subtype(cf->provider.wth);
            epan_dissect_run(edt, fts, &rec, fdata, NULL);
#else
        {
            Buffer buf;
            ws_buffer_init(&buf, fdata->cap_len);
            wtap_rec_init(&rec);
            read_ok = wtap_seek_read(cf->provider.wth, fdata->file_off, &rec, &buf, &err, &err_info_str);
            if (read_ok) {
                int fts = wtap_file_type_subtype(cf->provider.wth);
                tvbuff_t *tvb = tvb_new_real_data(ws_buffer_start_ptr(&buf),
                                                  rec.rec_header.packet_header.caplen,
                                                  rec.rec_header.packet_header.len);
                epan_dissect_run(edt, fts, &rec, tvb, fdata, NULL);
#endif
                /* Match addresses — for VoIP we match on addresses only,
                 * since RTP uses dynamic ports negotiated via SIP/SDP.  */
                {
                    gchar pkt_src[MAX_ADDR_STR_LEN], pkt_dst[MAX_ADDR_STR_LEN];
                    if (addr_is_mac) {
                        address_to_str_buf(&edt->pi.dl_src, pkt_src, sizeof(pkt_src));
                        address_to_str_buf(&edt->pi.dl_dst, pkt_dst, sizeof(pkt_dst));
                    } else {
                        address_to_str_buf(&edt->pi.net_src, pkt_src, sizeof(pkt_src));
                        address_to_str_buf(&edt->pi.net_dst, pkt_dst, sizeof(pkt_dst));
                    }
                    gboolean addr_ok =
                        (g_strcmp0(pkt_src, addr_a) == 0 && g_strcmp0(pkt_dst, addr_b) == 0) ||
                        (g_strcmp0(pkt_src, addr_b) == 0 && g_strcmp0(pkt_dst, addr_a) == 0);
                    /* For SIP, match on port; for RTP, match on addresses only */
                    gboolean port_ok =
                        ((guint32)port == edt->pi.srcport || (guint32)port == edt->pi.destport);

                    if (addr_ok && port_ok) {
                        matched++;
                        walk_voip_proto_tree(edt->tree, &ctx, 0);
                    }
                }

                epan_dissect_reset(edt);
#if VERSION_MINOR >= 6
        }
        wtap_rec_cleanup(&rec);
#else
            }
            wtap_rec_cleanup(&rec);
            ws_buffer_free(&buf);
        }
#endif
        if (err_info_str) {
            g_free(err_info_str);
        }

        if (matched % 50 == 0)
            circle_vis_pump_events();
    }

    epan_dissect_free(edt);

    info->matched_packets = matched;
    info->found = (matched > 0);

    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING,
           "VoIP analysis done: %u packets matched, found=%d, "
           "calls=%u, methods=%u, rtp_pkts=%u, rtp_ssrcs=%u",
           matched, info->found,
           info->call_ids ? g_list_length(info->call_ids) : 0,
           info->method_counts ? g_hash_table_size(info->method_counts) : 0,
           info->rtp_packet_count,
           info->rtp_ssrcs ? g_list_length(info->rtp_ssrcs) : 0);

    return info;
}

/* Generate a random but consistent color for a protocol name */
static guint32 generate_random_color(const gchar *protocol_name)
{
    if (!protocol_name || !*protocol_name)
        return 0x808080;
    
    /* Use hash of protocol name to generate consistent "random" color */
    guint32 hash = 0;
    const gchar *p = protocol_name;
    while (*p) {
        hash = hash * 31 + (guint8)*p;
        p++;
    }
    
    /* Generate RGB color from hash - avoid too dark or too light colors */
    guint8 r = (hash & 0xFF) | 0x40;  /* Ensure minimum brightness */
    guint8 g = ((hash >> 8) & 0xFF) | 0x40;
    guint8 b = ((hash >> 16) & 0xFF) | 0x40;
    
    /* Avoid pure colors that might conflict with TCP/UDP/ARP */
    if (r > 0xF0 && g < 0x20 && b < 0x20) r = 0xC0;  /* Avoid pure red */
    if (r < 0x20 && g > 0xF0 && b < 0x20) g = 0xC0;  /* Avoid pure green */
    if (r < 0x20 && g < 0x20 && b > 0xF0) b = 0xC0;  /* Avoid pure blue */
    if (r > 0xF0 && g > 0xF0 && b < 0x20) { r = 0xC0; g = 0xC0; }  /* Avoid pure yellow */
    if (r > 0xF0 && g < 0x20 && b > 0xF0) { r = 0xC0; b = 0xC0; }  /* Avoid pure magenta */
    if (r < 0x20 && g > 0xF0 && b > 0xF0) { g = 0xC0; b = 0xC0; }  /* Avoid pure cyan */
    
    return (r << 16) | (g << 8) | b;
}

guint32 packet_analyzer_get_protocol_color(const gchar *protocol_name)
{
    guint32 color;
    gpointer color_ptr;

    if (!protocol_name || !*protocol_name)
        return 0x808080;  /* Gray for unknown */

    if (!protocol_colors)
        init_protocol_colors();

    color_ptr = g_hash_table_lookup(protocol_colors, protocol_name);
    if (color_ptr) {
        color = GPOINTER_TO_UINT(color_ptr);
    } else {
        /* Not found - generate random but consistent color */
        color = generate_random_color(protocol_name);
        /* Cache it for future use */
        g_hash_table_insert(protocol_colors, g_strdup(protocol_name), GUINT_TO_POINTER(color));
    }

    return color;
}

GHashTable* packet_analyzer_get_protocols(void)
{
    if (!protocol_colors)
        init_protocol_colors();
    return protocol_colors;
}
