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

/* Free communication pair */
static void free_port_count(gpointer data)
{
    g_free(data);
}

static void free_comm_pair(gpointer data)
{
    comm_pair_t *pair = (comm_pair_t *)data;
    if (pair) {
        g_free(pair->src_addr);
        g_free(pair->dst_addr);
        g_free(pair->src_mac);
        g_free(pair->dst_mac);
        g_free(pair->src_ip);
        g_free(pair->dst_ip);
        g_free(pair->top_protocol);
        if (pair->dst_ports) {
            g_hash_table_destroy(pair->dst_ports);
        }
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
        pair->dst_ports = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, free_port_count);
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
    
    /* PRIORITY 3.5: Check for ICMP BEFORE transport-layer detection */
    /* ICMP doesn't have a ptype or ports, so we infer it from address type and lack of ports */
    /* This must happen BEFORE PRIORITY 3 to avoid being overridden by TCP/UDP */
    if (!protocol_name && (pinfo->src.type == AT_IPv4 || pinfo->src.type == AT_IPv6) && 
        (pinfo->srcport == 0 && pinfo->destport == 0)) {
        /* Could be ICMP - check if it's IPv6 for ICMPv6 */
        if (pinfo->src.type == AT_IPv6) {
            protocol_name = g_strdup("ICMPv6");
            ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING, "Packet %u: ✓ Detected ICMPv6 from IPv6 address and no ports", callback_count);
        } else {
            protocol_name = g_strdup("ICMP");
            ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING, "Packet %u: ✓ Detected ICMP from IPv4 address and no ports", callback_count);
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
        /* If we have ports but ptype is not set or unknown, infer TCP (most common) */
        else if (!protocol_name && (pinfo->srcport != 0 || pinfo->destport != 0)) {
            protocol_name = g_strdup("TCP");
            if (callback_count <= 10) {
                ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING, "Packet %u: Inferred TCP from ports (ptype=%u, ports: %u->%u)", 
                       callback_count, pinfo->ptype, pinfo->srcport, pinfo->destport);
            }
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

    /* Track destination port for this pair */
    if (pinfo->destport != 0 && pair->dst_ports) {
        gpointer port_key = GUINT_TO_POINTER((guint)pinfo->destport);
        guint64 *count = (guint64 *)g_hash_table_lookup(pair->dst_ports, port_key);
        if (count) {
            (*count)++;
        } else {
            count = g_new(guint64, 1);
            *count = 1;
            g_hash_table_insert(pair->dst_ports, port_key, count);
        }
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

    /* Allocate tap data structure */
    s_tap_data = g_new0(tap_data_t, 1);
    s_tap_data->pairs_table = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, free_comm_pair);
    s_tap_data->protocols_table = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, free_protocol_stats);
    s_tap_data->use_mac = use_mac;

    /* Register tap listener for "frame" tap (all packets) */
    error_string = register_tap_listener("frame", s_tap_data, NULL, 
                                        TL_REQUIRES_NOTHING,
                                        circle_vis_tap_reset_cb,
                                        circle_vis_tap_packet_cb,
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
        
        /* Initialize structures - FALSE, FALSE = don't create proto tree (saves memory) */
        /* NOTE: Full decode (TRUE, TRUE) causes crashes when accessing pinfo->layers */
        /* Using lightweight decode and relying on pinfo->current_proto instead */
        edt = epan_dissect_new(cf->epan, FALSE, FALSE);
        
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
