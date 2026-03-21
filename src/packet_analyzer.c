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

/* Wireshark 4.0 API compatibility:
 * In WS 4.0, field_info.value is fvalue_t (struct by value) and
 * fvalue_get_* functions take const fvalue_t*.
 * In WS 4.2+, field_info.value is fvalue_t* (pointer) used directly.
 */
#include "ws_version.h"
#if WIRESHARK_VERSION_MAJOR == 4 && WIRESHARK_VERSION_MINOR == 0
  #define PC_FI_VALUE(fi)         (&(fi)->value)
#else
  #define PC_FI_VALUE(fi)         ((fi)->value)
#endif
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
    

    

    /* Check if frame_data is available - do this early */
    /* Access pinfo->fd carefully - it might be causing the crash */
    if (!pinfo || !pinfo->fd) {
        return TAP_PACKET_DONT_REDRAW;
    }
    
    

    /* Check if pinfo->pool is valid */
    
    if (!pinfo->pool) {
        
        return TAP_PACKET_DONT_REDRAW;
    }
    

    /* Get protocol name from packet info */
    /* CRITICAL: Check application-layer protocols FIRST before transport-layer (UDP/TCP) */
    /* This ensures OSPF (over UDP) is detected as OSPF, not UDP */
    
    protocol_name = NULL;
    
    
    
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
            
        }
        /* Check for ICMP variants */
        else if (g_strcmp0(cp, "ICMP") == 0 || g_strcmp0(cp, "ICMPv6") == 0) {
            protocol_name = g_strdup(cp);
            
        }
        /* LLC-framed protocols (IEEE 802.2 LLC / SNAP encapsulated) */
        else if (g_strcmp0(cp, "STP") == 0 || g_strcmp0(cp, "RSTP") == 0 ||
                 g_strcmp0(cp, "MSTP") == 0 || g_strcmp0(cp, "PVST") == 0 ||
                 g_strcmp0(cp, "PVST+") == 0 || g_strcmp0(cp, "LLC") == 0 ||
                 g_strcmp0(cp, "VTP") == 0 || g_strcmp0(cp, "CDP") == 0 ||
                 g_strcmp0(cp, "DTP") == 0 || g_strcmp0(cp, "PAGP") == 0) {
            protocol_name = g_strdup(cp);
            
        }
        /* EtherType-specific non-IP protocols */
        else if (g_strcmp0(cp, "LLDP") == 0 || g_strcmp0(cp, "LACP") == 0 ||
                 g_strcmp0(cp, "EAPOL") == 0 || g_strcmp0(cp, "EAP") == 0 ||
                 g_strcmp0(cp, "MACsec") == 0 || g_strcmp0(cp, "VLAN") == 0 ||
                 g_strcmp0(cp, "802.1Q") == 0) {
            protocol_name = g_strdup(cp);

        }
        /* UDP application protocols — run over UDP but must be classified at app layer
         * so that "dhcp" / "bootp" / "dns" searches find the correct pairs. */
        else if (g_ascii_strcasecmp(cp, "DHCP") == 0 || g_ascii_strcasecmp(cp, "BOOTP") == 0 ||
                 g_ascii_strcasecmp(cp, "BOOTREPLY") == 0 || g_ascii_strcasecmp(cp, "BOOTREQUEST") == 0) {
            protocol_name = g_strdup("DHCP");
        }
        /* DNS — port 53 UDP/TCP; keep distinct from MDNS/LLMNR */
        else if (g_strcmp0(cp, "DNS") == 0) {
            protocol_name = g_strdup("DNS");
        }
        else if (g_strcmp0(cp, "MDNS") == 0) {
            protocol_name = g_strdup("MDNS");
        }
        /* IP-layer tunnel / security protocols (no TCP/UDP ports; would otherwise fall
         * back to the generic "IP" label and become unsearchable).                      */
        else if (g_strcmp0(cp, "GRE") == 0) {
            protocol_name = g_strdup("GRE");
        }
        else if (g_strcmp0(cp, "ESP") == 0) {
            protocol_name = g_strdup("ESP");
        }
        else if (g_strcmp0(cp, "AH") == 0) {
            protocol_name = g_strdup("AH");
        }
        else if (g_strcmp0(cp, "ISAKMP") == 0 || g_strcmp0(cp, "IKE") == 0 ||
                 g_strcmp0(cp, "IKEv2") == 0) {
            protocol_name = g_strdup("IKE");
        }
    }

    /* PRIORITY 1.3: ICMP/ICMPv6 via protocol layers — catches ICMP packets that
     * carry a data payload (echo request/reply, traceroute etc.) where the data
     * dissector runs last and sets current_proto to "Data" rather than "ICMP".
     * proto_is_frame_protocol() checks the pinfo->layers list, which is populated
     * unconditionally by each dissector in the chain.                           */
    if (!protocol_name && pinfo->layers) {
        if (proto_is_frame_protocol(pinfo->layers, "icmp")) {
            protocol_name = g_strdup("ICMP");
        } else if (proto_is_frame_protocol(pinfo->layers, "icmpv6")) {
            protocol_name = g_strdup("ICMPv6");
        }
    }

    /* PRIORITY 1.4: L2 protocol detection via pinfo->layers — same technique as ICMP
     * above.  TL_REQUIRES_NOTHING may leave current_proto as "Ethernet" even when the
     * frame carries ARP, STP, LLDP, LACP etc.  pinfo->layers is populated by every
     * dissector that ran, making it far more reliable than current_proto alone.      */
    if (!protocol_name && pinfo->layers) {
        if      (proto_is_frame_protocol(pinfo->layers, "arp"))   protocol_name = g_strdup("ARP");
        else if (proto_is_frame_protocol(pinfo->layers, "rarp"))  protocol_name = g_strdup("RARP");
        else if (proto_is_frame_protocol(pinfo->layers, "stp"))   protocol_name = g_strdup("STP");
        else if (proto_is_frame_protocol(pinfo->layers, "lldp"))  protocol_name = g_strdup("LLDP");
        else if (proto_is_frame_protocol(pinfo->layers, "lacp"))  protocol_name = g_strdup("LACP");
        else if (proto_is_frame_protocol(pinfo->layers, "cdp"))   protocol_name = g_strdup("CDP");
        else if (proto_is_frame_protocol(pinfo->layers, "vtp"))   protocol_name = g_strdup("VTP");
        else if (proto_is_frame_protocol(pinfo->layers, "eapol")) protocol_name = g_strdup("EAPOL");
        else if (proto_is_frame_protocol(pinfo->layers, "eap"))   protocol_name = g_strdup("EAP");
        else if (proto_is_frame_protocol(pinfo->layers, "llc"))   protocol_name = g_strdup("LLC");
        /* UDP application + IP tunnel/security protocols — layers fallback for when
         * lightweight dissection leaves current_proto as "UDP" or "IPv4".            */
        else if (proto_is_frame_protocol(pinfo->layers, "dhcp") ||
                 proto_is_frame_protocol(pinfo->layers, "bootp"))  protocol_name = g_strdup("DHCP");
        else if (proto_is_frame_protocol(pinfo->layers, "dns"))    protocol_name = g_strdup("DNS");
        else if (proto_is_frame_protocol(pinfo->layers, "mdns"))   protocol_name = g_strdup("MDNS");
        else if (proto_is_frame_protocol(pinfo->layers, "gre"))    protocol_name = g_strdup("GRE");
        else if (proto_is_frame_protocol(pinfo->layers, "esp"))    protocol_name = g_strdup("ESP");
        else if (proto_is_frame_protocol(pinfo->layers, "ah"))     protocol_name = g_strdup("AH");
        else if (proto_is_frame_protocol(pinfo->layers, "isakmp")) protocol_name = g_strdup("IKE");
    }

    /* PRIORITY 1.5: Check for routing protocols by port (when current_proto is missing) */
    /* This is a fallback when current_proto doesn't work */
    if (!protocol_name && (pinfo->srcport != 0 || pinfo->destport != 0)) {
        guint16 port = (pinfo->srcport != 0) ? pinfo->srcport : pinfo->destport;
        
        /* OSPF uses port 89 */
        if (port == 89) {
            protocol_name = g_strdup("OSPF");
            
        }
        /* BGP uses port 179 */
        else if (port == 179) {
            protocol_name = g_strdup("BGP");
            
        }
        /* RIP uses port 520 */
        else if (port == 520) {
            protocol_name = g_strdup("RIP");

        }
        /* DHCP/BOOTP: server port 67, client port 68 (UDP) */
        else if (port == 67 || port == 68) {
            protocol_name = g_strdup("DHCP");
        }
        /* DNS: port 53 (UDP/TCP) */
        else if (port == 53) {
            protocol_name = g_strdup("DNS");
        }
        /* mDNS: port 5353 (UDP multicast) */
        else if (port == 5353) {
            protocol_name = g_strdup("MDNS");
        }
        /* IKE/ISAKMP: port 500 (IKE), port 4500 (IKE NAT-T) */
        else if (port == 500 || port == 4500) {
            protocol_name = g_strdup("IKE");
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
                    
                }
            }
        }
    }
    
    /* PRIORITY 3.5: IP packets with no ports — could be IGMP, IP fragments,
     * GRE, ESP, etc.  ICMP is caught by PRIORITY 1 (current_proto == "ICMP")
     * or PRIORITY 1.3 (proto layers fallback for ICMP-with-data-payload).
     * For IGMP, lightweight dissection (TL_REQUIRES_NOTHING) may not run the
     * IGMP dissector, so current_proto stays "IPv4" and the packet misses
     * PRIORITY 1.  Detect IGMP by checking for IPv4 multicast destinations
     * (224.0.0.0/4) with no transport layer.                                  */
    if (!protocol_name && pinfo->ptype == PT_NONE &&
        pinfo->srcport == 0 && pinfo->destport == 0 &&
        (pinfo->src.type == AT_IPv4 || pinfo->dst.type == AT_IPv4)) {
        /* Check if destination is IPv4 multicast (224.0.0.0/4) */
        if (pinfo->dst.type == AT_IPv4 && pinfo->dst.len == 4) {
            const guint8 *dst_bytes = (const guint8 *)pinfo->dst.data;
            if (dst_bytes && (dst_bytes[0] >= 224 && dst_bytes[0] <= 239)) {
                protocol_name = g_strdup("IGMP");
                
            }
        }
    }
    
    /* PRIORITY 3: Check packet type (ptype) - for transport-layer protocols */
    /* Only use this if no application-layer protocol was found */
    if (!protocol_name) {
        if (pinfo->ptype == PT_TCP) {
            protocol_name = g_strdup("TCP");
            
        } else if (pinfo->ptype == PT_UDP) {
            protocol_name = g_strdup("UDP");
            
        } else if (pinfo->ptype == PT_SCTP) {
            protocol_name = g_strdup("SCTP");
            
        } else if (pinfo->ptype == PT_DCCP) {
            protocol_name = g_strdup("DCCP");
            
        }
        /* If we have ports but ptype is not set or unknown, do NOT blindly
         * infer TCP.  This catches IP fragments where the first fragment
         * carries a UDP header (ports populated) but ptype might not be set
         * correctly by lightweight dissection.  Let it fall through to the
         * generic "IP" fallback instead.                                     */
        else if (!protocol_name && (pinfo->srcport != 0 || pinfo->destport != 0)) {
            
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
        
    }
    
    /* Ensure we have a valid protocol name */
    if (!protocol_name || !*protocol_name) {
        if (protocol_name) {
            g_free(protocol_name);
        }
        protocol_name = g_strdup("Unknown");
    }

    /* In MAC mode, if MACsec is anywhere in the frame protocol stack, label the
     * pair "MACsec" regardless of what inner protocols were found.  This handles
     * both encrypted MACsec (current_proto already = "MACsec") and plaintext
     * MACsec (current_proto = inner protocol such as "TCP"). */
    if (tap_data->use_mac && pinfo->layers &&
            proto_is_frame_protocol(pinfo->layers, "macsec")) {
        g_free(protocol_name);
        protocol_name = g_strdup("MACsec");
    }

    /* Get addresses based on MAC or IP preference */
    /* Log address types for debugging - be very careful accessing pinfo fields */
    
    
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
            
            src_addr = mac_src;
            dst_addr = mac_dst;
        } else {
            /* Address type doesn't match - skip this packet */
            
            g_free(protocol_name);
            return TAP_PACKET_DONT_REDRAW;
        }
    } else {
        /* Looking for IP addresses - check both src and dst are IP */
        
        if (ip_src && ip_dst) {
            
            src_addr = ip_src;
            dst_addr = ip_dst;
        } else {
            /* Address type doesn't match - skip this packet */
            
            g_free(protocol_name);
            return TAP_PACKET_DONT_REDRAW;
        }
    }

    if (!src_addr || !dst_addr) {
        ws_log(WS_LOG_DOMAIN, LOG_LEVEL_ERROR, "Packet %u: address_to_str returned NULL (src=%p, dst=%p)", 
               callback_count, src_addr, dst_addr);
        g_free(protocol_name);
        return TAP_PACKET_DONT_REDRAW;
    }
    
    

    /* Get or create pair - addresses from pinfo->pool are valid for the lifetime of the packet */
    /* We need to copy them since we're storing them in our hash table */
    if (!src_addr || !dst_addr) {
        
        g_free(protocol_name);
        return TAP_PACKET_DONT_REDRAW;
    }
    
    pair = get_or_create_pair(tap_data->pairs_table, src_addr, dst_addr, tap_data->use_mac);
    
    if (!pair) {
        ws_log(WS_LOG_DOMAIN, LOG_LEVEL_ERROR, "Packet %u: get_or_create_pair returned NULL", callback_count);
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
    
    

    /* Update statistics */
    pair->packet_count++;
    
    /* Safely get packet length */
    if (pinfo->fd) {
        packet_len = pinfo->fd->pkt_len;
        if (packet_len > 0) {
            pair->byte_count += packet_len;
        }
    } else {
        
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
        
    } else if (is_layer4) {
        /* Layer 4 protocol - always prefer it over Layer 3/2 */
        should_update = TRUE;
        
    } else if (is_layer3 && (g_strcmp0(pair->top_protocol, "Ethernet") == 0 || 
                              g_strcmp0(pair->top_protocol, "Unknown") == 0)) {
        /* Layer 3 protocol - prefer it over Layer 2 or Unknown */
        should_update = TRUE;
        
    } else if (is_layer2 && g_strcmp0(pair->top_protocol, "Unknown") == 0) {
        /* Layer 2 protocol - prefer it over Unknown */
        should_update = TRUE;

    } else if (!is_layer4 && !is_layer3 && !is_layer2) {
        /* Application / tunnel protocol (DHCP, GRE, ESP, AH, IKE, OSPF…) —
         * more informative than a generic transport label.  Promote over UDP,
         * TCP, IP, Ethernet, or Unknown so that e.g. DHCP pairs are not
         * permanently stuck with "UDP" as their top_protocol.              */
        const gchar *ep = pair->top_protocol;
        if (g_strcmp0(ep, "UDP")      == 0 || g_strcmp0(ep, "TCP")      == 0 ||
            g_strcmp0(ep, "IP")       == 0 || g_strcmp0(ep, "Unknown")  == 0 ||
            g_strcmp0(ep, "Ethernet") == 0) {
            should_update = TRUE;
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

/* Return a human-readable name for WAN/non-Ethernet encapsulations that have no
 * Ethernet MAC addresses, or NULL for standard Ethernet/Wi-Fi/Token-Ring captures.
 * When non-NULL is returned the caller MUST NOT free the string (it is a literal).
 * PacketCircle automatically disables MAC mode for these capture types.             */
static const gchar *detect_wan_encap_name(capture_file *cf)
{
    if (!cf || !cf->provider.wth)
        return NULL;
    int encap = wtap_file_encap(cf->provider.wth);
    switch (encap) {
    case WTAP_ENCAP_FRELAY:
    case WTAP_ENCAP_FRELAY_WITH_PHDR:  return "Frame Relay";
    case WTAP_ENCAP_PPP:
    case WTAP_ENCAP_PPP_WITH_PHDR:
    case WTAP_ENCAP_PPP_ETHER:         return "PPP";
    case WTAP_ENCAP_CHDLC:
    case WTAP_ENCAP_CHDLC_WITH_PHDR:   return "Cisco HDLC";
    case WTAP_ENCAP_LAPB:              return "LAPB (X.25)";
    case WTAP_ENCAP_RAW_IP:
    case WTAP_ENCAP_RAW_IP4:
    case WTAP_ENCAP_RAW_IP6:           return "Raw IP";
    case WTAP_ENCAP_SLIP:              return "SLIP";
    case WTAP_ENCAP_ATM_RFC1483:
    case WTAP_ENCAP_ATM_PDUS:
    case WTAP_ENCAP_ATM_PDUS_UNTRUNCATED: return "ATM";
    case WTAP_ENCAP_ARCNET:
    case WTAP_ENCAP_ARCNET_LINUX:      return "ARCNET";
    default:                           return NULL;
    }
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
        /* WH: guard against rare allocation failure — skip the probe and fall through
         * to the normal tap path which will still classify traffic correctly.       */
        if (edt) {
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
        } /* end if (edt) — WH: NULL guard closes here */
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
            ctx->rssi = (gint16)fvalue_get_sinteger(PC_FI_VALUE(fi));
            ctx->rssi_found = TRUE;
        }
        /* Fallback RSSI from wlan_radio */
        if (g_strcmp0(abbrev, "wlan_radio.signal_dbm") == 0 && !ctx->rssi_found) {
            ctx->rssi = (gint16)fvalue_get_sinteger(PC_FI_VALUE(fi));
            ctx->rssi_found = TRUE;
        }
        /* Channel */
        if (g_strcmp0(abbrev, "wlan_radio.channel") == 0 && ctx->channel == 0) {
            ctx->channel = (guint16)fvalue_get_uinteger(PC_FI_VALUE(fi));
        }
        /* Frame type */
        if (g_strcmp0(abbrev, "wlan.fc.type") == 0) {
            ctx->fc_type = (guint8)fvalue_get_uinteger(PC_FI_VALUE(fi));
            ctx->has_type = TRUE;
        }
        /* Frame subtype */
        if (g_strcmp0(abbrev, "wlan.fc.type_subtype") == 0) {
            ctx->fc_subtype = (guint8)fvalue_get_uinteger(PC_FI_VALUE(fi));
        }
        /* Retry flag */
        if (g_strcmp0(abbrev, "wlan.fc.retry") == 0) {
            ctx->retry = (fvalue_get_uinteger(PC_FI_VALUE(fi)) != 0);
        }
        /* Reason code (deauth / disassoc management frames) */
        if (g_strcmp0(abbrev, "wlan.fixed.reason_code") == 0 && !ctx->reason_found) {
            ctx->reason_code = (guint16)fvalue_get_uinteger(PC_FI_VALUE(fi));
            ctx->reason_found = TRUE;
        }
        /* PHY type for Wi-Fi standard identification */
        if (g_strcmp0(abbrev, "wlan_radio.phy") == 0 && !ctx->phy_found) {
            ctx->phy = (guint8)fvalue_get_uinteger(PC_FI_VALUE(fi));
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
        ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO, "packet_analyzer_analyze: cf is NULL");
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
        ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO, "packet_analyzer_analyze: file not ready (state=%d, frames=%p)", 
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

    /* Detect WAN / non-Ethernet encapsulations that have no Ethernet MACs.
     * For these capture types MAC mode would produce zero pairs, so force IP. */
    const gchar *wan_name = detect_wan_encap_name(cf);
    if (wan_name && use_mac && !is_wifi) {
        ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO,
               "WAN encap '%s' detected — forcing IP mode (no Ethernet MACs available)",
               wan_name);
        use_mac = FALSE;
    }

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
        /* WH: guard — epan_dissect_new() can return NULL on OOM; in that case we
         * skip the frame-iteration loop and return an empty (but valid) result so
         * the UI doesn't crash.  The tap listener is still registered so live-capture
         * frames would still arrive, but for loaded files we'd have an empty pair list. */
        if (!edt) {
            ws_log(WS_LOG_DOMAIN, LOG_LEVEL_ERROR,
                   "packet_analyzer_analyze: epan_dissect_new() returned NULL — skipping frame scan");
            goto cleanup_analysis;
        }

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
        /* WH: cleanup_analysis label — jumped to from epan_dissect_new() NULL guard */
cleanup_analysis:
        if (edt)
            epan_dissect_free(edt);
        edt = NULL;

        /* Log how many packets were processed */
        if (has_filter) {
            ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO, "Processed %u packets out of %u total (%u filtered out by display filter)",
                   processed_count, cf->count, filtered_count);
        } else {
            ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO, "Processed %u packets out of %u total", processed_count, cf->count);
        }
        
        /* Log hash table sizes */
        guint pairs_count = g_hash_table_size(s_tap_data->pairs_table);
        guint protocols_count = g_hash_table_size(s_tap_data->protocols_table);
        ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO, "Collected %u pairs and %u protocols", pairs_count, protocols_count);
    } else {
        ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO, "Skipping packet processing: state=%d, frames=%p, count=%u", 
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
    result->encap_name = wan_name ? g_strdup(wan_name) : NULL;

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
            ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO, "Pair %s->%s had invalid top_protocol, set to Unknown", 
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

    if (result->encap_name) {
        g_free(result->encap_name);
        result->encap_name = NULL;
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
        ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO, "extract_tls_info: capture not ready");
        return info;
    }

    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO,
           "TLS analysis: addr_a=%s, addr_b=%s, port=%u, is_mac=%d",
           addr_a ? addr_a : "(null)", addr_b ? addr_b : "(null)",
           port, addr_is_mac);
    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO,
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
    if (!edt) { /* WH: guard against allocation failure */
        ws_log(WS_LOG_DOMAIN, LOG_LEVEL_ERROR, "TLS: epan_dissect_new() returned NULL");
        return info;
    }

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

    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO,
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
    if (!edt) { /* WH: guard against allocation failure */
        ws_log(WS_LOG_DOMAIN, LOG_LEVEL_ERROR, "HTTP: epan_dissect_new() returned NULL");
        return info;
    }

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

    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO,
           "SMB analysis: addr_a=%s, addr_b=%s, port=%u, is_mac=%d",
           addr_a ? addr_a : "(null)", addr_b ? addr_b : "(null)",
           port, addr_is_mac);

    smb_walk_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.info = info;

    epan_dissect_t *edt = epan_dissect_new(cf->epan, TRUE, TRUE);
    if (!edt) { /* WH: guard against allocation failure */
        ws_log(WS_LOG_DOMAIN, LOG_LEVEL_ERROR, "SMB: epan_dissect_new() returned NULL");
        return info;
    }

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

    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO,
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

    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO,
           "Kerberos analysis: addr_a=%s, addr_b=%s, port=%u, is_mac=%d",
           addr_a ? addr_a : "(null)", addr_b ? addr_b : "(null)",
           port, addr_is_mac);

    krb_walk_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.info = info;

    epan_dissect_t *edt = epan_dissect_new(cf->epan, TRUE, TRUE);
    if (!edt) { /* WH: guard against allocation failure */
        ws_log(WS_LOG_DOMAIN, LOG_LEVEL_ERROR, "Kerberos: epan_dissect_new() returned NULL");
        return info;
    }

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

    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO,
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

    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO,
           "Email analysis: addr_a=%s, addr_b=%s, port=%u, is_mac=%d",
           addr_a ? addr_a : "(null)", addr_b ? addr_b : "(null)",
           port, addr_is_mac);

    email_walk_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.info = info;

    epan_dissect_t *edt = epan_dissect_new(cf->epan, TRUE, TRUE);
    if (!edt) { /* WH: guard against allocation failure */
        ws_log(WS_LOG_DOMAIN, LOG_LEVEL_ERROR, "Email: epan_dissect_new() returned NULL");
        return info;
    }

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

    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO,
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

    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO,
           "SQL analysis: addr_a=%s, addr_b=%s, port=%u, is_mac=%d",
           addr_a ? addr_a : "(null)", addr_b ? addr_b : "(null)",
           port, addr_is_mac);

    sql_walk_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.info = info;

    epan_dissect_t *edt = epan_dissect_new(cf->epan, TRUE, TRUE);
    if (!edt) { /* WH: guard against allocation failure */
        ws_log(WS_LOG_DOMAIN, LOG_LEVEL_ERROR, "SQL: epan_dissect_new() returned NULL");
        return info;
    }

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

    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO,
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

    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO,
           "VoIP analysis: addr_a=%s, addr_b=%s, port=%u, is_mac=%d",
           addr_a ? addr_a : "(null)", addr_b ? addr_b : "(null)",
           port, addr_is_mac);

    voip_walk_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.info = info;

    epan_dissect_t *edt = epan_dissect_new(cf->epan, TRUE, TRUE);
    if (!edt) { /* WH: guard against allocation failure */
        ws_log(WS_LOG_DOMAIN, LOG_LEVEL_ERROR, "VoIP: epan_dissect_new() returned NULL");
        return info;
    }

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

    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO,
           "VoIP analysis done: %u packets matched, found=%d, "
           "calls=%u, methods=%u, rtp_pkts=%u, rtp_ssrcs=%u",
           matched, info->found,
           info->call_ids ? g_list_length(info->call_ids) : 0,
           info->method_counts ? g_hash_table_size(info->method_counts) : 0,
           info->rtp_packet_count,
           info->rtp_ssrcs ? g_list_length(info->rtp_ssrcs) : 0);

    return info;
}

/* ------------------------------------------------------------------ */
/* General Layer-2 Frame Information Extraction                       */
/* ------------------------------------------------------------------ */

/* Known EtherType values → human-readable names */
static const gchar* ethertype_name(guint16 et)
{
    switch (et) {
        case 0x0800: return "IPv4";
        case 0x0806: return "ARP";
        case 0x0835: return "RARP";
        case 0x86DD: return "IPv6";
        case 0x8100: return "VLAN (802.1Q)";
        case 0x88A8: return "QinQ (802.1ad)";
        case 0x8847: return "MPLS Unicast";
        case 0x8848: return "MPLS Multicast";
        case 0x8809: return "LACP/Slow Protocols";
        case 0x88CC: return "LLDP";
        case 0x888E: return "802.1X (EAPOL)";
        case 0x88E5: return "MACsec (802.1AE)";
        case 0x88F5: return "MRP";
        case 0x9100: return "QinQ (old)";
        default:     return NULL;
    }
}

/* Known LLC DSAP values */
static const gchar* llc_dsap_name(guint8 dsap)
{
    switch (dsap & 0xFE) {  /* mask off I/G bit */
        case 0x00: return "Null";
        case 0x02: return "LLC Sub-layer Mgmt";
        case 0x06: return "ARPANET IP";
        case 0x42: return "STP (802.1D)";
        case 0xAA: return "SNAP";
        case 0xE0: return "Novell IPX";
        case 0xF0: return "NetBIOS";
        case 0xFE: return "OSI";
        default:   return NULL;
    }
}

typedef struct {
    l2_info_t *info;
} l2_walk_ctx_t;

static void walk_l2_proto_tree(proto_node *node, l2_walk_ctx_t *ctx, int depth)
{
    if (!node || depth > 20) return;

    field_info *fi = node->finfo;
    if (fi && fi->hfinfo && fi->hfinfo->abbrev) {
        const gchar *abbrev = fi->hfinfo->abbrev;
        gchar label[ITEM_LABEL_LENGTH];
        label[0] = '\0';

        /* Ethernet type field */
        if (g_strcmp0(abbrev, "eth.type") == 0) {
            guint16 et = (guint16)fvalue_get_uinteger(PC_FI_VALUE(fi));
            gchar key[16];
            g_snprintf(key, sizeof(key), "0x%04X", et);
            gpointer prev = g_hash_table_lookup(ctx->info->ethertype_counts, key);
            guint cnt = prev ? GPOINTER_TO_UINT(prev) + 1 : 1;
            g_hash_table_insert(ctx->info->ethertype_counts, g_strdup(key), GUINT_TO_POINTER(cnt));
            /* Build human-readable entry */
            const gchar *ename = ethertype_name(et);
            gchar entry[64];
            if (ename)
                g_snprintf(entry, sizeof(entry), "%s (%s)", key, ename);
            else
                g_snprintf(entry, sizeof(entry), "%s", key);
            add_unique_string(&ctx->info->ethertype_names, entry);
        }

        /* VLAN ID */
        if (g_strcmp0(abbrev, "vlan.id") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) add_unique_string(&ctx->info->vlan_ids, val);
            g_free(val);
        }

        /* LLC DSAP */
        if (g_strcmp0(abbrev, "llc.dsap") == 0) {
            guint8 dsap = (guint8)fvalue_get_uinteger(PC_FI_VALUE(fi));
            guint8 ssap = 0;
            /* Try to find sibling ssap node */
            proto_node *sib = node->next;
            while (sib) {
                field_info *sf = sib->finfo;
                if (sf && sf->hfinfo && g_strcmp0(sf->hfinfo->abbrev, "llc.ssap") == 0) {
                    ssap = (guint8)fvalue_get_uinteger(PC_FI_VALUE(sf));
                    break;
                }
                sib = sib->next;
            }
            const gchar *dname = llc_dsap_name(dsap);
            gchar entry[80];
            if (dname)
                g_snprintf(entry, sizeof(entry), "DSAP=0x%02X SSAP=0x%02X (%s)", dsap, ssap, dname);
            else
                g_snprintf(entry, sizeof(entry), "DSAP=0x%02X SSAP=0x%02X", dsap, ssap);
            add_unique_string(&ctx->info->llc_dsap_ssap, entry);
            /* Count this DSAP/SSAP pair for the protocol breakdown table */
            gchar llc_key[16];
            g_snprintf(llc_key, sizeof(llc_key), "0x%02X/0x%02X",
                       dsap & 0xFE, ssap & 0xFE);
            gpointer prev_cnt = g_hash_table_lookup(ctx->info->llc_counts, llc_key);
            guint llc_cnt = prev_cnt ? GPOINTER_TO_UINT(prev_cnt) + 1 : 1;
            g_hash_table_insert(ctx->info->llc_counts, g_strdup(llc_key),
                                GUINT_TO_POINTER(llc_cnt));
        }
    }

    for (proto_node *child = node->first_child; child; child = child->next)
        walk_l2_proto_tree(child, ctx, depth + 1);
}

void packet_analyzer_free_l2_info(l2_info_t *info)
{
    if (!info) return;
    if (info->ethertype_counts) g_hash_table_destroy(info->ethertype_counts);
    if (info->ethertype_names)  g_list_free_full(info->ethertype_names, g_free);
    if (info->vlan_ids)         g_list_free_full(info->vlan_ids, g_free);
    if (info->llc_dsap_ssap)    g_list_free_full(info->llc_dsap_ssap, g_free);
    if (info->llc_counts)       g_hash_table_destroy(info->llc_counts);
    g_free(info);
}

l2_info_t* packet_analyzer_extract_l2_info(capture_file *cf,
                                            const gchar *addr_a,
                                            const gchar *addr_b,
                                            gboolean addr_is_mac)
{
    l2_info_t *info = g_new0(l2_info_t, 1);
    info->ethertype_counts = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
    info->llc_counts       = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);

    if (!cf || cf->state != FILE_READ_DONE || !cf->provider.frames || cf->count == 0)
        return info;

    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO,
           "L2 analysis: addr_a=%s addr_b=%s", addr_a ? addr_a : "(null)", addr_b ? addr_b : "(null)");

    l2_walk_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.info = info;

    epan_dissect_t *edt = epan_dissect_new(cf->epan, TRUE, TRUE);
    if (!edt) { /* WH: guard against allocation failure */
        ws_log(WS_LOG_DOMAIN, LOG_LEVEL_ERROR, "L2: epan_dissect_new() returned NULL");
        return info;
    }
    guint32 matched = 0;

    for (guint32 framenum = 1; framenum <= cf->count; framenum++) {
        frame_data *fdata = frame_data_sequence_find(cf->provider.frames, framenum);
        if (!fdata || fdata->file_off < 0) continue;

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
                {
                    gchar pkt_src[MAX_ADDR_STR_LEN], pkt_dst[MAX_ADDR_STR_LEN];
                    address_to_str_buf(&edt->pi.dl_src, pkt_src, sizeof(pkt_src));
                    address_to_str_buf(&edt->pi.dl_dst, pkt_dst, sizeof(pkt_dst));
                    gboolean addr_ok =
                        (g_strcmp0(pkt_src, addr_a) == 0 && g_strcmp0(pkt_dst, addr_b) == 0) ||
                        (g_strcmp0(pkt_src, addr_b) == 0 && g_strcmp0(pkt_dst, addr_a) == 0);
                    if (addr_ok) {
                        matched++;
                        walk_l2_proto_tree(edt->tree, &ctx, 0);
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
        if (err_info_str) g_free(err_info_str);
        if (matched % 50 == 0) circle_vis_pump_events();
    }

    epan_dissect_free(edt);
    info->matched_packets = matched;
    info->found = (matched > 0 && (info->ethertype_names || info->llc_dsap_ssap || info->vlan_ids));
    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO, "L2 analysis done: %u matched, found=%d", matched, info->found);
    return info;
}

/* ------------------------------------------------------------------ */
/* STP Information Extraction                                         */
/* ------------------------------------------------------------------ */

typedef struct {
    stp_info_t *info;
} stp_walk_ctx_t;

/* WH: Rewritten to capture the full STP field set — root/bridge priority+ext,
 * all four timer fields, per-type BPDU counters, RSTP flag bits, and PVST+. */
static void walk_stp_proto_tree(proto_node *node, stp_walk_ctx_t *ctx, int depth)
{
    if (!node || depth > 20) return;

    field_info *fi = node->finfo;
    if (fi && fi->hfinfo && fi->hfinfo->abbrev) {
        const gchar *abbrev = fi->hfinfo->abbrev;
        gchar label[ITEM_LABEL_LENGTH];
        label[0] = '\0';

        /* ── Root bridge ─────────────────────────────────────── */
        if (g_strcmp0(abbrev, "stp.root.hw") == 0 && !ctx->info->root_bridge_mac) {
            fill_label_compat(fi, label);
            ctx->info->root_bridge_mac = label_value(label);
        }
        /* Root bridge priority (FT_UINT16, mask 0xf000 — returns masked value) */
        if (g_strcmp0(abbrev, "stp.root.pri") == 0)
            ctx->info->root_bridge_priority = (guint16)fvalue_get_uinteger(PC_FI_VALUE(fi));
        /* Root bridge system ID extension (FT_UINT16, mask 0x0fff) */
        if (g_strcmp0(abbrev, "stp.root.ext") == 0)
            ctx->info->root_bridge_ext = (guint16)fvalue_get_uinteger(PC_FI_VALUE(fi));
        if (g_strcmp0(abbrev, "stp.root.pathcost") == 0)
            ctx->info->root_path_cost = (guint32)fvalue_get_uinteger(PC_FI_VALUE(fi));

        /* ── Local bridge ────────────────────────────────────── */
        if (g_strcmp0(abbrev, "stp.bridge.hw") == 0 && !ctx->info->bridge_mac) {
            fill_label_compat(fi, label);
            ctx->info->bridge_mac = label_value(label);
        }
        if (g_strcmp0(abbrev, "stp.bridge.pri") == 0)
            ctx->info->bridge_priority = (guint16)fvalue_get_uinteger(PC_FI_VALUE(fi));
        /* Bridge system ID extension — equals VLAN ID in PVST+ */
        if (g_strcmp0(abbrev, "stp.bridge.ext") == 0)
            ctx->info->bridge_ext = (guint16)fvalue_get_uinteger(PC_FI_VALUE(fi));
        /* Full 16-bit port identifier: top nibble = priority (×16), bottom 12 = port# */
        if (g_strcmp0(abbrev, "stp.port") == 0)
            ctx->info->port_id = (guint16)fvalue_get_uinteger(PC_FI_VALUE(fi));

        /* ── Timers (FT_DOUBLE in Wireshark 4.x — use label string) ─ */
        if (g_strcmp0(abbrev, "stp.hello") == 0 && !ctx->info->hello_time_str) {
            fill_label_compat(fi, label);
            ctx->info->hello_time_str = label_value(label);
        }
        if (g_strcmp0(abbrev, "stp.max_age") == 0 && !ctx->info->max_age_str) {
            fill_label_compat(fi, label);
            ctx->info->max_age_str = label_value(label);
        }
        if (g_strcmp0(abbrev, "stp.forward") == 0 && !ctx->info->forward_delay_str) {
            fill_label_compat(fi, label);
            ctx->info->forward_delay_str = label_value(label);
        }
        if (g_strcmp0(abbrev, "stp.msg_age") == 0 && !ctx->info->msg_age_str) {
            fill_label_compat(fi, label);
            ctx->info->msg_age_str = label_value(label);
        }

        /* ── BPDU type — count each type, remember first label ───── */
        if (g_strcmp0(abbrev, "stp.type") == 0) {
            guint32 btype = fvalue_get_uinteger(PC_FI_VALUE(fi));
            switch (btype) {
                case 0x00:
                    ctx->info->config_bpdu_count++;
                    if (!ctx->info->bpdu_type)
                        ctx->info->bpdu_type = g_strdup("Configuration");
                    break;
                case 0x80:
                    ctx->info->tcn_bpdu_count++;
                    ctx->info->topology_change_count++;  /* TCN itself is a TC event */
                    if (!ctx->info->bpdu_type)
                        ctx->info->bpdu_type = g_strdup("TCN");
                    break;
                case 0x02:
                    ctx->info->rst_bpdu_count++;
                    if (!ctx->info->bpdu_type)
                        ctx->info->bpdu_type = g_strdup("RST/MST");
                    break;
                default: {
                    gchar tmp[32];
                    g_snprintf(tmp, sizeof(tmp), "0x%02X", btype);
                    if (!ctx->info->bpdu_type)
                        ctx->info->bpdu_type = g_strdup(tmp);
                }
            }
        }
        /* Topology Change flag set inside a Configuration BPDU */
        if (g_strcmp0(abbrev, "stp.flags.tc") == 0 && fvalue_get_uinteger(PC_FI_VALUE(fi)))
            ctx->info->topology_change_count++;
        /* Topology Change Acknowledgment */
        if (g_strcmp0(abbrev, "stp.flags.tca") == 0 && fvalue_get_uinteger(PC_FI_VALUE(fi)))
            ctx->info->flags_tca = TRUE;

        /* ── Protocol variant ────────────────────────────────── */
        if (g_strcmp0(abbrev, "stp.version") == 0 && !ctx->info->stp_variant) {
            guint32 ver = fvalue_get_uinteger(PC_FI_VALUE(fi));
            switch (ver) {
                case 0:  ctx->info->stp_variant = g_strdup("STP");  break;
                case 2:  ctx->info->stp_variant = g_strdup("RSTP"); break;
                case 3:  ctx->info->stp_variant = g_strdup("MSTP"); break;
                default: ctx->info->stp_variant = g_strdup("STP");
            }
        }

        /* ── RSTP / MSTP per-port flag bits ──────────────────── */
        if (g_strcmp0(abbrev, "stp.flags.proposal") == 0 && fvalue_get_uinteger(PC_FI_VALUE(fi)))
            ctx->info->flags_proposal   = TRUE;
        if (g_strcmp0(abbrev, "stp.flags.agreement") == 0 && fvalue_get_uinteger(PC_FI_VALUE(fi)))
            ctx->info->flags_agreement  = TRUE;
        if (g_strcmp0(abbrev, "stp.flags.forward") == 0 && fvalue_get_uinteger(PC_FI_VALUE(fi)))
            ctx->info->flags_forwarding = TRUE;
        if (g_strcmp0(abbrev, "stp.flags.learn") == 0 && fvalue_get_uinteger(PC_FI_VALUE(fi)))
            ctx->info->flags_learning   = TRUE;
        /* Port role — may differ across packets; collect unique values */
        if (g_strcmp0(abbrev, "stp.flags.role") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) add_unique_string(&ctx->info->port_roles, val);
            g_free(val);
        }

        /* ── PVST+ (Cisco Per-VLAN Spanning Tree Plus) ───────── */
        if (g_strcmp0(abbrev, "pvst.origvlan")  == 0 ||
            g_strcmp0(abbrev, "pvst+.origvlan") == 0) {
            ctx->info->is_pvst = TRUE;
            if (!ctx->info->pvst_vlan)
                ctx->info->pvst_vlan = (guint16)fvalue_get_uinteger(PC_FI_VALUE(fi));
        }
    }

    for (proto_node *child = node->first_child; child; child = child->next)
        walk_stp_proto_tree(child, ctx, depth + 1);
}

void packet_analyzer_free_stp_info(stp_info_t *info)
{
    if (!info) return;
    g_free(info->root_bridge_mac);
    g_free(info->bridge_mac);
    g_free(info->bpdu_type);
    g_free(info->stp_variant);
    /* WH: free new timer label strings */
    g_free(info->hello_time_str);
    g_free(info->max_age_str);
    g_free(info->forward_delay_str);
    g_free(info->msg_age_str);
    if (info->port_roles) g_list_free_full(info->port_roles, g_free);
    g_free(info);
}

stp_info_t* packet_analyzer_extract_stp_info(capture_file *cf,
                                              const gchar *addr_a,
                                              const gchar *addr_b,
                                              gboolean addr_is_mac)
{
    stp_info_t *info = g_new0(stp_info_t, 1);

    if (!cf || cf->state != FILE_READ_DONE || !cf->provider.frames || cf->count == 0)
        return info;

    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO, "STP analysis: addr_a=%s addr_b=%s",
           addr_a ? addr_a : "(null)", addr_b ? addr_b : "(null)");

    stp_walk_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.info = info;

    epan_dissect_t *edt = epan_dissect_new(cf->epan, TRUE, TRUE);
    if (!edt) { /* WH: guard against allocation failure */
        ws_log(WS_LOG_DOMAIN, LOG_LEVEL_ERROR, "STP: epan_dissect_new() returned NULL");
        return info;
    }
    guint32 matched = 0;

    for (guint32 framenum = 1; framenum <= cf->count; framenum++) {
        frame_data *fdata = frame_data_sequence_find(cf->provider.frames, framenum);
        if (!fdata || fdata->file_off < 0) continue;

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
                {
                    gchar pkt_src[MAX_ADDR_STR_LEN], pkt_dst[MAX_ADDR_STR_LEN];
                    address_to_str_buf(&edt->pi.dl_src, pkt_src, sizeof(pkt_src));
                    address_to_str_buf(&edt->pi.dl_dst, pkt_dst, sizeof(pkt_dst));
                    gboolean addr_ok =
                        (g_strcmp0(pkt_src, addr_a) == 0 && g_strcmp0(pkt_dst, addr_b) == 0) ||
                        (g_strcmp0(pkt_src, addr_b) == 0 && g_strcmp0(pkt_dst, addr_a) == 0);
                    if (addr_ok) {
                        matched++;
                        walk_stp_proto_tree(edt->tree, &ctx, 0);
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
        if (err_info_str) g_free(err_info_str);
        if (matched % 50 == 0) circle_vis_pump_events();
    }

    epan_dissect_free(edt);
    info->matched_packets = matched;
    if (!info->stp_variant && matched > 0) info->stp_variant = g_strdup("STP");
    /* WH: derive is_root — the STP root advertises itself as the root bridge */
    if (info->bridge_mac && info->root_bridge_mac &&
        g_ascii_strcasecmp(info->bridge_mac, info->root_bridge_mac) == 0)
        info->is_root = TRUE;
    info->found = (matched > 0);
    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO,
           "STP analysis done: %u matched, variant=%s, is_root=%d",
           matched, info->stp_variant ? info->stp_variant : "?", info->is_root);
    return info;
}

/* ------------------------------------------------------------------ */
/* LLDP Information Extraction                                        */
/* ------------------------------------------------------------------ */

typedef struct {
    lldp_info_t *info;
} lldp_walk_ctx_t;

static void walk_lldp_proto_tree(proto_node *node, lldp_walk_ctx_t *ctx, int depth)
{
    if (!node || depth > 20) return;

    field_info *fi = node->finfo;
    if (fi && fi->hfinfo && fi->hfinfo->abbrev) {
        const gchar *abbrev = fi->hfinfo->abbrev;
        gchar label[ITEM_LABEL_LENGTH];
        label[0] = '\0';

        if (g_strcmp0(abbrev, "lldp.chassis.id") == 0 && !ctx->info->chassis_id) {
            fill_label_compat(fi, label);
            ctx->info->chassis_id = label_value(label);
        }
        if (g_strcmp0(abbrev, "lldp.port.id") == 0 && !ctx->info->port_id) {
            fill_label_compat(fi, label);
            ctx->info->port_id = label_value(label);
        }
        if (g_strcmp0(abbrev, "lldp.system.name") == 0 && !ctx->info->system_name) {
            fill_label_compat(fi, label);
            ctx->info->system_name = label_value(label);
        }
        if (g_strcmp0(abbrev, "lldp.system.desc") == 0 && !ctx->info->system_description) {
            fill_label_compat(fi, label);
            ctx->info->system_description = label_value(label);
        }
        if (g_strcmp0(abbrev, "lldp.port.desc") == 0 && !ctx->info->port_description) {
            fill_label_compat(fi, label);
            ctx->info->port_description = label_value(label);
        }
        if (g_strcmp0(abbrev, "lldp.time_to_live") == 0) {
            ctx->info->ttl = (guint)fvalue_get_uinteger(PC_FI_VALUE(fi));
        }
        if (g_strcmp0(abbrev, "lldp.system.cap.s") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            add_unique_string(&ctx->info->capabilities, val);
            g_free(val);
        }
        if (g_strcmp0(abbrev, "lldp.system.cap.e") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            add_unique_string(&ctx->info->enabled_capabilities, val);
            g_free(val);
        }
        if (g_strcmp0(abbrev, "lldp.mgn.addr.ip4") == 0 || g_strcmp0(abbrev, "lldp.mgn.addr.ip6") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            add_unique_string(&ctx->info->management_addresses, val);
            g_free(val);
        }
    }

    for (proto_node *child = node->first_child; child; child = child->next)
        walk_lldp_proto_tree(child, ctx, depth + 1);
}

void packet_analyzer_free_lldp_info(lldp_info_t *info)
{
    if (!info) return;
    g_free(info->chassis_id);
    g_free(info->port_id);
    g_free(info->system_name);
    g_free(info->system_description);
    g_free(info->port_description);
    if (info->capabilities)          g_list_free_full(info->capabilities, g_free);
    if (info->enabled_capabilities)  g_list_free_full(info->enabled_capabilities, g_free);
    if (info->management_addresses)  g_list_free_full(info->management_addresses, g_free);
    if (info->vlan_names)            g_list_free_full(info->vlan_names, g_free);
    g_free(info);
}

lldp_info_t* packet_analyzer_extract_lldp_info(capture_file *cf,
                                                const gchar *addr_a,
                                                const gchar *addr_b,
                                                gboolean addr_is_mac)
{
    lldp_info_t *info = g_new0(lldp_info_t, 1);

    if (!cf || cf->state != FILE_READ_DONE || !cf->provider.frames || cf->count == 0)
        return info;

    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO, "LLDP analysis: addr_a=%s addr_b=%s",
           addr_a ? addr_a : "(null)", addr_b ? addr_b : "(null)");

    lldp_walk_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.info = info;

    epan_dissect_t *edt = epan_dissect_new(cf->epan, TRUE, TRUE);
    if (!edt) { /* WH: guard against allocation failure */
        ws_log(WS_LOG_DOMAIN, LOG_LEVEL_ERROR, "LLDP: epan_dissect_new() returned NULL");
        return info;
    }
    guint32 matched = 0;

    for (guint32 framenum = 1; framenum <= cf->count; framenum++) {
        frame_data *fdata = frame_data_sequence_find(cf->provider.frames, framenum);
        if (!fdata || fdata->file_off < 0) continue;

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
                {
                    gchar pkt_src[MAX_ADDR_STR_LEN], pkt_dst[MAX_ADDR_STR_LEN];
                    address_to_str_buf(&edt->pi.dl_src, pkt_src, sizeof(pkt_src));
                    address_to_str_buf(&edt->pi.dl_dst, pkt_dst, sizeof(pkt_dst));
                    gboolean addr_ok =
                        (g_strcmp0(pkt_src, addr_a) == 0 && g_strcmp0(pkt_dst, addr_b) == 0) ||
                        (g_strcmp0(pkt_src, addr_b) == 0 && g_strcmp0(pkt_dst, addr_a) == 0);
                    if (addr_ok) {
                        matched++;
                        walk_lldp_proto_tree(edt->tree, &ctx, 0);
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
        if (err_info_str) g_free(err_info_str);
        if (matched % 50 == 0) circle_vis_pump_events();
    }

    epan_dissect_free(edt);
    info->matched_packets = matched;
    info->found = (matched > 0 && (info->chassis_id || info->system_name));
    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO, "LLDP analysis done: %u matched", matched);
    return info;
}

/* ------------------------------------------------------------------ */
/* LACP Information Extraction                                        */
/* ------------------------------------------------------------------ */

typedef struct {
    lacp_info_t *info;
} lacp_walk_ctx_t;

/* Decode LACP state flags to a string (e.g. "ACT TIM AGG SYN COL DIS") */
static gchar* lacp_state_string(guint8 state)
{
    gchar buf[64];
    buf[0] = '\0';
    if (state & 0x01) g_strlcat(buf, "ACT ", sizeof(buf));   /* Activity */
    if (state & 0x02) g_strlcat(buf, "TIM ", sizeof(buf));   /* Timeout */
    if (state & 0x04) g_strlcat(buf, "AGG ", sizeof(buf));   /* Aggregation */
    if (state & 0x08) g_strlcat(buf, "SYN ", sizeof(buf));   /* Synchronization */
    if (state & 0x10) g_strlcat(buf, "COL ", sizeof(buf));   /* Collecting */
    if (state & 0x20) g_strlcat(buf, "DIS ", sizeof(buf));   /* Distributing */
    if (state & 0x40) g_strlcat(buf, "DEF ", sizeof(buf));   /* Defaulted */
    if (state & 0x80) g_strlcat(buf, "EXP ", sizeof(buf));   /* Expired */
    if (buf[0] == '\0') g_strlcat(buf, "none", sizeof(buf));
    /* trim trailing space */
    gsize len = strlen(buf);
    if (len > 0 && buf[len-1] == ' ') buf[len-1] = '\0';
    return g_strdup(buf);
}

static void walk_lacp_proto_tree(proto_node *node, lacp_walk_ctx_t *ctx, int depth)
{
    if (!node || depth > 20) return;

    field_info *fi = node->finfo;
    if (fi && fi->hfinfo && fi->hfinfo->abbrev) {
        const gchar *abbrev = fi->hfinfo->abbrev;
        gchar label[ITEM_LABEL_LENGTH];
        label[0] = '\0';

        if (g_strcmp0(abbrev, "lacp.actor.sys") == 0 && !ctx->info->actor_system) {
            fill_label_compat(fi, label);
            ctx->info->actor_system = label_value(label);
        }
        if (g_strcmp0(abbrev, "lacp.actor.key") == 0)
            ctx->info->actor_key = (guint16)fvalue_get_uinteger(PC_FI_VALUE(fi));
        if (g_strcmp0(abbrev, "lacp.actor.port") == 0)
            ctx->info->actor_port = (guint16)fvalue_get_uinteger(PC_FI_VALUE(fi));
        if (g_strcmp0(abbrev, "lacp.actor.state") == 0)
            ctx->info->actor_state = (guint8)fvalue_get_uinteger(PC_FI_VALUE(fi));

        if (g_strcmp0(abbrev, "lacp.partner.sys") == 0 && !ctx->info->partner_system) {
            fill_label_compat(fi, label);
            ctx->info->partner_system = label_value(label);
        }
        if (g_strcmp0(abbrev, "lacp.partner.key") == 0)
            ctx->info->partner_key = (guint16)fvalue_get_uinteger(PC_FI_VALUE(fi));
        if (g_strcmp0(abbrev, "lacp.partner.port") == 0)
            ctx->info->partner_port = (guint16)fvalue_get_uinteger(PC_FI_VALUE(fi));
        if (g_strcmp0(abbrev, "lacp.partner.state") == 0)
            ctx->info->partner_state = (guint8)fvalue_get_uinteger(PC_FI_VALUE(fi));
    }

    for (proto_node *child = node->first_child; child; child = child->next)
        walk_lacp_proto_tree(child, ctx, depth + 1);
}

void packet_analyzer_free_lacp_info(lacp_info_t *info)
{
    if (!info) return;
    g_free(info->actor_system);
    g_free(info->partner_system);
    g_free(info);
}

lacp_info_t* packet_analyzer_extract_lacp_info(capture_file *cf,
                                                const gchar *addr_a,
                                                const gchar *addr_b,
                                                gboolean addr_is_mac)
{
    lacp_info_t *info = g_new0(lacp_info_t, 1);

    if (!cf || cf->state != FILE_READ_DONE || !cf->provider.frames || cf->count == 0)
        return info;

    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO, "LACP analysis: addr_a=%s addr_b=%s",
           addr_a ? addr_a : "(null)", addr_b ? addr_b : "(null)");

    lacp_walk_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.info = info;

    epan_dissect_t *edt = epan_dissect_new(cf->epan, TRUE, TRUE);
    if (!edt) { /* WH: guard against allocation failure */
        ws_log(WS_LOG_DOMAIN, LOG_LEVEL_ERROR, "LACP: epan_dissect_new() returned NULL");
        return info;
    }
    guint32 matched = 0;

    for (guint32 framenum = 1; framenum <= cf->count; framenum++) {
        frame_data *fdata = frame_data_sequence_find(cf->provider.frames, framenum);
        if (!fdata || fdata->file_off < 0) continue;

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
                {
                    gchar pkt_src[MAX_ADDR_STR_LEN], pkt_dst[MAX_ADDR_STR_LEN];
                    address_to_str_buf(&edt->pi.dl_src, pkt_src, sizeof(pkt_src));
                    address_to_str_buf(&edt->pi.dl_dst, pkt_dst, sizeof(pkt_dst));
                    gboolean addr_ok =
                        (g_strcmp0(pkt_src, addr_a) == 0 && g_strcmp0(pkt_dst, addr_b) == 0) ||
                        (g_strcmp0(pkt_src, addr_b) == 0 && g_strcmp0(pkt_dst, addr_a) == 0);
                    if (addr_ok) {
                        matched++;
                        walk_lacp_proto_tree(edt->tree, &ctx, 0);
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
        if (err_info_str) g_free(err_info_str);
        if (matched % 50 == 0) circle_vis_pump_events();
    }

    epan_dissect_free(edt);
    info->matched_packets = matched;
    info->found = (matched > 0 && info->actor_system);
    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO, "LACP analysis done: %u matched", matched);
    return info;
}

/* ------------------------------------------------------------------ */
/* 802.1Q VLAN Information Extraction                                 */
/* ------------------------------------------------------------------ */

typedef struct {
    vlan_info_t *info;
    guint8       vlan_tags_in_frame; /* count of vlan.id nodes seen this frame */
} vlan_walk_ctx_t;

static void walk_vlan_proto_tree(proto_node *node, vlan_walk_ctx_t *ctx, int depth)
{
    if (!node || depth > 16) return;
    field_info *fi = node->finfo;
    if (fi && fi->hfinfo) {
        const char *abbrev = fi->hfinfo->abbrev;
        char label[ITEM_LABEL_LENGTH];

        /* VLAN ID — count per-ID frame distribution */
        if (g_strcmp0(abbrev, "vlan.id") == 0) {
            guint32 vid = fvalue_get_uinteger(PC_FI_VALUE(fi));
            gchar key[8];
            g_snprintf(key, sizeof(key), "%u", vid);
            gpointer prev = g_hash_table_lookup(ctx->info->vlan_id_counts, key);
            guint cnt = prev ? GPOINTER_TO_UINT(prev) + 1 : 1;
            g_hash_table_insert(ctx->info->vlan_id_counts, g_strdup(key), GUINT_TO_POINTER(cnt));
            ctx->vlan_tags_in_frame++;
            if (ctx->vlan_tags_in_frame > 1)
                ctx->info->qinq_count++;
        }

        /* PCP (Priority Code Point) — bits 15-13 of the TCI */
        if (g_strcmp0(abbrev, "vlan.priority") == 0) {
            guint32 pcp = fvalue_get_uinteger(PC_FI_VALUE(fi));
            if (pcp < 8)
                ctx->info->pcp_counts[pcp]++;
        }

        /* DEI / CFI (Drop Eligible Indicator) */
        if (g_strcmp0(abbrev, "vlan.dei") == 0 ||
            g_strcmp0(abbrev, "vlan.cfi") == 0) {
            fill_label_compat(fi, label);
            if (fvalue_get_uinteger(PC_FI_VALUE(fi)) != 0)
                ctx->info->dei_count++;
        }
    }
    for (proto_node *child = node->first_child; child; child = child->next)
        walk_vlan_proto_tree(child, ctx, depth + 1);
}

void packet_analyzer_free_vlan_info(vlan_info_t *info)
{
    if (!info) return;
    if (info->vlan_id_counts) g_hash_table_destroy(info->vlan_id_counts);
    g_free(info);
}

vlan_info_t* packet_analyzer_extract_vlan_info(capture_file *cf,
                                                const gchar *addr_a,
                                                const gchar *addr_b,
                                                gboolean addr_is_mac)
{
    vlan_info_t *info = g_new0(vlan_info_t, 1);
    info->vlan_id_counts = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);

    if (!cf || cf->state != FILE_READ_DONE || !cf->provider.frames || cf->count == 0)
        return info;

    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO, "VLAN analysis: addr_a=%s addr_b=%s",
           addr_a ? addr_a : "(null)", addr_b ? addr_b : "(null)");

    epan_dissect_t *edt = epan_dissect_new(cf->epan, TRUE, TRUE);
    if (!edt) return info;

    guint32 matched = 0;

    for (guint32 framenum = 1; framenum <= cf->count; framenum++) {
        frame_data *fdata = frame_data_sequence_find(cf->provider.frames, framenum);
        if (!fdata || fdata->file_off < 0) continue;

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
                {
                    gchar pkt_src[MAX_ADDR_STR_LEN], pkt_dst[MAX_ADDR_STR_LEN];
                    address_to_str_buf(&edt->pi.dl_src, pkt_src, sizeof(pkt_src));
                    address_to_str_buf(&edt->pi.dl_dst, pkt_dst, sizeof(pkt_dst));
                    gboolean addr_ok =
                        (g_strcmp0(pkt_src, addr_a) == 0 && g_strcmp0(pkt_dst, addr_b) == 0) ||
                        (g_strcmp0(pkt_src, addr_b) == 0 && g_strcmp0(pkt_dst, addr_a) == 0);
                    if (addr_ok) {
                        matched++;
                        vlan_walk_ctx_t ctx;
                        memset(&ctx, 0, sizeof(ctx));
                        ctx.info = info;
                        walk_vlan_proto_tree(edt->tree, &ctx, 0);
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
        if (err_info_str) g_free(err_info_str);
        if (framenum % 500 == 0) circle_vis_pump_events();
    }

    epan_dissect_free(edt);
    info->matched_packets = matched;
    info->found = (matched > 0 && g_hash_table_size(info->vlan_id_counts) > 0);
    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO, "VLAN analysis done: %u matched", matched);
    return info;
}

/* ------------------------------------------------------------------ */
/* EAP / 802.1X Information Extraction                                */
/* ------------------------------------------------------------------ */

typedef struct {
    eap_info_t *info;
} eap_walk_ctx_t;

static const gchar* eap_type_name(guint8 type)
{
    switch (type) {
        case 1:   return "Identity";
        case 2:   return "Notification";
        case 3:   return "NAK";
        case 4:   return "MD5-Challenge";
        case 13:  return "EAP-TLS";
        case 17:  return "LEAP";
        case 21:  return "EAP-TTLS";
        case 25:  return "PEAP";
        case 26:  return "MS-CHAPv2";
        case 43:  return "EAP-FAST";
        case 52:  return "EAP-PWD";
        case 254: return "Expanded";
        default:  return NULL;
    }
}

static const gchar* eapol_type_name(guint8 type)
{
    switch (type) {
        case 0: return "EAP Packet";
        case 1: return "Start";
        case 2: return "Logoff";
        case 3: return "Key";
        case 4: return "Encapsulated-ASF-Alert";
        default: return "Unknown";
    }
}

static void walk_eap_proto_tree(proto_node *node, eap_walk_ctx_t *ctx, int depth)
{
    if (!node || depth > 20) return;

    field_info *fi = node->finfo;
    if (fi && fi->hfinfo && fi->hfinfo->abbrev) {
        const gchar *abbrev = fi->hfinfo->abbrev;
        gchar label[ITEM_LABEL_LENGTH];
        label[0] = '\0';

        /* EAP Code (Request/Response/Success/Failure) */
        if (g_strcmp0(abbrev, "eap.code") == 0) {
            guint8 code = (guint8)fvalue_get_uinteger(PC_FI_VALUE(fi));
            switch (code) {
                case 1: ctx->info->request_count++;  break;
                case 2: ctx->info->response_count++; break;
                case 3: ctx->info->success_count++;  break;
                case 4: ctx->info->failure_count++;  break;
            }
        }
        /* EAP Type */
        if (g_strcmp0(abbrev, "eap.type") == 0) {
            guint8 etype = (guint8)fvalue_get_uinteger(PC_FI_VALUE(fi));
            const gchar *tname = eap_type_name(etype);
            if (tname) {
                add_unique_string(&ctx->info->eap_types, tname);
            } else {
                gchar tmp[32];
                g_snprintf(tmp, sizeof(tmp), "Type %u", etype);
                add_unique_string(&ctx->info->eap_types, tmp);
            }
        }
        /* EAP Identity */
        if (g_strcmp0(abbrev, "eap.identity") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) add_unique_string(&ctx->info->identities, val);
            g_free(val);
        }
        /* EAPOL Type */
        if (g_strcmp0(abbrev, "eapol.type") == 0) {
            guint8 etype = (guint8)fvalue_get_uinteger(PC_FI_VALUE(fi));
            add_unique_string(&ctx->info->eapol_types, eapol_type_name(etype));
        }
    }

    for (proto_node *child = node->first_child; child; child = child->next)
        walk_eap_proto_tree(child, ctx, depth + 1);
}

void packet_analyzer_free_eap_info(eap_info_t *info)
{
    if (!info) return;
    if (info->eap_types)   g_list_free_full(info->eap_types, g_free);
    if (info->identities)  g_list_free_full(info->identities, g_free);
    if (info->eapol_types) g_list_free_full(info->eapol_types, g_free);
    g_free(info);
}

eap_info_t* packet_analyzer_extract_eap_info(capture_file *cf,
                                              const gchar *addr_a,
                                              const gchar *addr_b,
                                              gboolean addr_is_mac)
{
    eap_info_t *info = g_new0(eap_info_t, 1);

    if (!cf || cf->state != FILE_READ_DONE || !cf->provider.frames || cf->count == 0)
        return info;

    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO, "EAP analysis: addr_a=%s addr_b=%s",
           addr_a ? addr_a : "(null)", addr_b ? addr_b : "(null)");

    eap_walk_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.info = info;

    epan_dissect_t *edt = epan_dissect_new(cf->epan, TRUE, TRUE);
    if (!edt) { /* WH: guard against allocation failure */
        ws_log(WS_LOG_DOMAIN, LOG_LEVEL_ERROR, "EAP: epan_dissect_new() returned NULL");
        return info;
    }
    guint32 matched = 0;

    for (guint32 framenum = 1; framenum <= cf->count; framenum++) {
        frame_data *fdata = frame_data_sequence_find(cf->provider.frames, framenum);
        if (!fdata || fdata->file_off < 0) continue;

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
                {
                    gchar pkt_src[MAX_ADDR_STR_LEN], pkt_dst[MAX_ADDR_STR_LEN];
                    address_to_str_buf(&edt->pi.dl_src, pkt_src, sizeof(pkt_src));
                    address_to_str_buf(&edt->pi.dl_dst, pkt_dst, sizeof(pkt_dst));
                    gboolean addr_ok =
                        (g_strcmp0(pkt_src, addr_a) == 0 && g_strcmp0(pkt_dst, addr_b) == 0) ||
                        (g_strcmp0(pkt_src, addr_b) == 0 && g_strcmp0(pkt_dst, addr_a) == 0);
                    if (addr_ok) {
                        matched++;
                        walk_eap_proto_tree(edt->tree, &ctx, 0);
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
        if (err_info_str) g_free(err_info_str);
        if (matched % 50 == 0) circle_vis_pump_events();
    }

    epan_dissect_free(edt);
    info->matched_packets = matched;
    info->found = (matched > 0 && (info->eap_types || info->success_count || info->failure_count));
    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO, "EAP analysis done: %u matched", matched);
    return info;
}

/* ------------------------------------------------------------------ */
/* MACsec Information Extraction                                      */
/* ------------------------------------------------------------------ */

typedef struct {
    macsec_info_t *info;
    /* per-frame state — reset by the caller before each frame walk */
    gboolean macsec_dissector_fired; /* any macsec.* field seen this frame  */
    gboolean tvb_fallback_done;      /* TVB raw-byte parse already applied   */
} macsec_walk_ctx_t;

static void walk_macsec_proto_tree(proto_node *node, macsec_walk_ctx_t *ctx, int depth)
{
    if (!node || depth > 20) return;

    field_info *fi = node->finfo;
    if (fi && fi->hfinfo && fi->hfinfo->abbrev) {
        const gchar *abbrev = fi->hfinfo->abbrev;
        gchar label[ITEM_LABEL_LENGTH];
        label[0] = '\0';

        /* ── Primary path: use the MACsec dissector's own fields ── */

        /* Any macsec.* field confirms the dissector ran for this frame */
        if (!ctx->macsec_dissector_fired && strncmp(abbrev, "macsec", 6) == 0) {
            ctx->macsec_dissector_fired = TRUE;
            ctx->info->packet_count_protected++;
        }

        /* TCI byte — two field names exist across Wireshark versions */
        if (g_strcmp0(abbrev, "macsec.tci")    == 0 ||
            g_strcmp0(abbrev, "macsec.tci_an") == 0) {
            ctx->info->tci_flags = (guint8)fvalue_get_uinteger(PC_FI_VALUE(fi));
        }

        /* Individual TCI sub-bits */
        if (g_strcmp0(abbrev, "macsec.tci.e") == 0 && fvalue_get_uinteger(PC_FI_VALUE(fi)))
            ctx->info->encryption_enabled = TRUE;
        if (g_strcmp0(abbrev, "macsec.tci.sc") == 0 && fvalue_get_uinteger(PC_FI_VALUE(fi)))
            ctx->info->sci_present = TRUE;

        /* Association Number (0–3) */
        if (g_strcmp0(abbrev, "macsec.an") == 0) {
            guint32 an = fvalue_get_uinteger(PC_FI_VALUE(fi));
            if (an < 4) ctx->info->an_counts[an]++;
        }

        /* Packet Number */
        if (g_strcmp0(abbrev, "macsec.pn") == 0) {
            guint32 pn = fvalue_get_uinteger(PC_FI_VALUE(fi));
            if (!ctx->info->pn_valid) {
                ctx->info->min_pn = ctx->info->max_pn = pn;
                ctx->info->pn_valid = TRUE;
            } else {
                if (pn < ctx->info->min_pn) ctx->info->min_pn = pn;
                if (pn > ctx->info->max_pn) ctx->info->max_pn = pn;
            }
        }

        /* SCI string */
        if (g_strcmp0(abbrev, "macsec.sci") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) add_unique_string(&ctx->info->sci_values, val);
            g_free(val);
        }

        /* ── Fallback path: parse SecTAG bytes directly from the TVB ──
         * Triggered when we see eth.type == 0x88E5 but no macsec.* fields
         * have appeared yet (dissector disabled / version mismatch).
         * fi->start + fi->length gives the byte offset right after the
         * EtherType field, which is where the 802.1AE SecTAG begins.
         * This handles both untagged (offset 14) and VLAN-tagged frames
         * (offset 18+) automatically.                                    */
        if (!ctx->tvb_fallback_done &&
            !ctx->macsec_dissector_fired &&
            g_strcmp0(abbrev, "eth.type") == 0 &&
            fvalue_get_uinteger(PC_FI_VALUE(fi)) == 0x88E5 &&
            fi->ds_tvb != NULL) {

            gint sectag_off = fi->start + fi->length;
            gint remaining  = tvb_reported_length_remaining(fi->ds_tvb, sectag_off);

            if (remaining >= 6) {
                guint8 tci_an = tvb_get_guint8(fi->ds_tvb, sectag_off);
                /* byte 1 = Short Length (skip), bytes 2-5 = Packet Number */
                guint32 pn = tvb_get_ntohl(fi->ds_tvb, sectag_off + 2);

                ctx->info->tci_flags         = tci_an & 0xFC;     /* TCI bits */
                ctx->info->encryption_enabled = (tci_an & 0x08) != 0;
                ctx->info->sci_present        = (tci_an & 0x20) != 0;
                guint8 an = tci_an & 0x03;
                if (an < 4) ctx->info->an_counts[an]++;

                if (!ctx->info->pn_valid) {
                    ctx->info->min_pn = ctx->info->max_pn = pn;
                    ctx->info->pn_valid = TRUE;
                } else {
                    if (pn < ctx->info->min_pn) ctx->info->min_pn = pn;
                    if (pn > ctx->info->max_pn) ctx->info->max_pn = pn;
                }

                /* SCI: 8 bytes at SecTAG offset 6 (present only when SC=1) */
                if (ctx->info->sci_present && remaining >= 14) {
                    guint8 s[8];
                    for (int i = 0; i < 8; i++)
                        s[i] = tvb_get_guint8(fi->ds_tvb, sectag_off + 6 + i);
                    gchar sci_str[30];
                    g_snprintf(sci_str, sizeof(sci_str),
                               "%02X:%02X:%02X:%02X:%02X:%02X/%04X",
                               s[0], s[1], s[2], s[3], s[4], s[5],
                               (guint)(s[6] << 8) | s[7]);
                    add_unique_string(&ctx->info->sci_values, sci_str);
                }

                ctx->info->packet_count_protected++;
                ctx->tvb_fallback_done = TRUE;
            }
        }
    }

    for (proto_node *child = node->first_child; child; child = child->next)
        walk_macsec_proto_tree(child, ctx, depth + 1);
}

void packet_analyzer_free_macsec_info(macsec_info_t *info)
{
    if (!info) return;
    if (info->sci_values) g_list_free_full(info->sci_values, g_free);
    g_free(info);
}

macsec_info_t* packet_analyzer_extract_macsec_info(capture_file *cf,
                                                    const gchar *addr_a,
                                                    const gchar *addr_b,
                                                    gboolean addr_is_mac)
{
    macsec_info_t *info = g_new0(macsec_info_t, 1);

    if (!cf || cf->state != FILE_READ_DONE || !cf->provider.frames || cf->count == 0)
        return info;

    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO, "MACsec analysis: addr_a=%s addr_b=%s",
           addr_a ? addr_a : "(null)", addr_b ? addr_b : "(null)");

    epan_dissect_t *edt = epan_dissect_new(cf->epan, TRUE, TRUE);
    if (!edt) { /* WH: guard against allocation failure */
        ws_log(WS_LOG_DOMAIN, LOG_LEVEL_ERROR, "MACsec: epan_dissect_new() returned NULL");
        return info;
    }
    guint32 matched = 0;

    for (guint32 framenum = 1; framenum <= cf->count; framenum++) {
        frame_data *fdata = frame_data_sequence_find(cf->provider.frames, framenum);
        if (!fdata || fdata->file_off < 0) continue;

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
                {
                    gchar pkt_src[MAX_ADDR_STR_LEN], pkt_dst[MAX_ADDR_STR_LEN];
                    address_to_str_buf(&edt->pi.dl_src, pkt_src, sizeof(pkt_src));
                    address_to_str_buf(&edt->pi.dl_dst, pkt_dst, sizeof(pkt_dst));
                    gboolean addr_ok =
                        (g_strcmp0(pkt_src, addr_a) == 0 && g_strcmp0(pkt_dst, addr_b) == 0) ||
                        (g_strcmp0(pkt_src, addr_b) == 0 && g_strcmp0(pkt_dst, addr_a) == 0);
                    if (addr_ok) {
                        matched++;
                        /* Fresh per-frame context so fallback flags reset each frame */
                        macsec_walk_ctx_t fctx;
                        memset(&fctx, 0, sizeof(fctx));
                        fctx.info = info;
                        walk_macsec_proto_tree(edt->tree, &fctx, 0);
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
        if (err_info_str) g_free(err_info_str);
        if (matched % 50 == 0) circle_vis_pump_events();
    }

    epan_dissect_free(edt);
    info->matched_packets = matched;
    /* found = TRUE whenever there are matching frames (EtherType 0x88E5
     * confirms they are MACsec).  SecTAG sub-fields may be absent when
     * the MACsec dissector preference is off or the capture is truncated. */
    info->found = (matched > 0);
    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO, "MACsec analysis done: %u matched, %u protected",
           matched, info->packet_count_protected);
    return info;
}

/* ================================================================== */
/*  ARP Information Extraction                                        */
/* ================================================================== */

typedef struct {
    arp_info_t *info;
    /* Temporary tables for anomaly detection (live for extraction duration) */
    GHashTable *requested_ips;  /* ip_str → TRUE: IPs seen in ARP requests */
    GHashTable *ip_to_macs;     /* ip_str → GHashTable(mac_str → TRUE) */
    /* Per-packet state; reset after each packet's tree walk */
    guint16 opcode;             /* 0=none, 1=request, 2=reply */
    gchar   sender_mac[64];
    gchar   sender_ip[64];
    gchar   target_ip[64];
} arp_walk_ctx_t;

static void walk_arp_proto_tree(proto_node *node, arp_walk_ctx_t *ctx, int depth)
{
    if (!node || depth > 15) return;

    field_info *fi = node->finfo;
    if (fi && fi->hfinfo && fi->hfinfo->abbrev) {
        const gchar *abbrev = fi->hfinfo->abbrev;
        gchar label[ITEM_LABEL_LENGTH];
        label[0] = '\0';

        if (g_strcmp0(abbrev, "arp.opcode") == 0) {
            ctx->opcode = (guint16)fvalue_get_uinteger(PC_FI_VALUE(fi));
        } else if (g_strcmp0(abbrev, "arp.src.hw_mac") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) g_strlcpy(ctx->sender_mac, val, sizeof(ctx->sender_mac));
            g_free(val);
        } else if (g_strcmp0(abbrev, "arp.src.proto_ipv4") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) g_strlcpy(ctx->sender_ip, val, sizeof(ctx->sender_ip));
            g_free(val);
        } else if (g_strcmp0(abbrev, "arp.dst.proto_ipv4") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) g_strlcpy(ctx->target_ip, val, sizeof(ctx->target_ip));
            g_free(val);
        }
    }

    for (proto_node *child = node->first_child; child; child = child->next)
        walk_arp_proto_tree(child, ctx, depth + 1);
}

/* Process one ARP packet after walking its tree; resets per-packet ctx state. */
static void process_arp_packet(arp_walk_ctx_t *ctx)
{
    if (ctx->opcode != 0) {
        arp_info_t *info = ctx->info;

        if (ctx->opcode == 1) {
            /* ARP Request */
            info->request_count++;
            if (ctx->target_ip[0])
                g_hash_table_replace(ctx->requested_ips,
                                     g_strdup(ctx->target_ip), GINT_TO_POINTER(1));
        } else if (ctx->opcode == 2) {
            /* ARP Reply */
            info->reply_count++;

            /* Gratuitous: sender IP == target IP in reply */
            if (ctx->sender_ip[0] && ctx->target_ip[0] &&
                g_strcmp0(ctx->sender_ip, ctx->target_ip) == 0)
                info->gratuitous_count++;

            /* Record MAC -> IP mapping and update IP->MACs table */
            if (ctx->sender_mac[0] && ctx->sender_ip[0]) {
                gchar entry[256];
                g_snprintf(entry, sizeof(entry), "%s -> %s", ctx->sender_mac, ctx->sender_ip);
                add_unique_string(&info->mac_ip_mappings, entry);

                GHashTable *mac_set = (GHashTable*)g_hash_table_lookup(
                    ctx->ip_to_macs, ctx->sender_ip);
                if (!mac_set) {
                    mac_set = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
                    g_hash_table_insert(ctx->ip_to_macs,
                                        g_strdup(ctx->sender_ip), mac_set);
                }
                if (!g_hash_table_lookup(mac_set, ctx->sender_mac))
                    g_hash_table_insert(mac_set,
                                        g_strdup(ctx->sender_mac), GINT_TO_POINTER(1));
            }
        }
    }

    /* Reset per-packet state */
    ctx->opcode      = 0;
    ctx->sender_mac[0] = '\0';
    ctx->sender_ip[0]  = '\0';
    ctx->target_ip[0]  = '\0';
}

void packet_analyzer_free_arp_info(arp_info_t *info)
{
    if (!info) return;
    if (info->mac_ip_mappings)      g_list_free_full(info->mac_ip_mappings,      g_free);
    if (info->ip_conflict_warnings) g_list_free_full(info->ip_conflict_warnings, g_free);
    if (info->unsolicited_warnings) g_list_free_full(info->unsolicited_warnings, g_free);
    g_free(info);
}

arp_info_t* packet_analyzer_extract_arp_info(capture_file *cf,
                                              const gchar *addr_a,
                                              const gchar *addr_b,
                                              gboolean addr_is_mac)
{
    (void)addr_a; (void)addr_b; (void)addr_is_mac;  /* scan entire trace */

    arp_info_t *info = g_new0(arp_info_t, 1);
    if (!cf || cf->state != FILE_READ_DONE || !cf->provider.frames || cf->count == 0)
        return info;

    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO, "ARP analysis: scanning entire trace (%u frames)", cf->count);

    arp_walk_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.info = info;
    ctx.requested_ips = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
    /* outer key freed by g_free, inner GHashTable destroyed by g_hash_table_destroy */
    ctx.ip_to_macs = g_hash_table_new_full(g_str_hash, g_str_equal,
                                            g_free,
                                            (GDestroyNotify)g_hash_table_destroy);

    epan_dissect_t *edt = epan_dissect_new(cf->epan, TRUE, TRUE);
    if (!edt) { /* WH: guard against allocation failure */
        ws_log(WS_LOG_DOMAIN, LOG_LEVEL_ERROR, "ARP: epan_dissect_new() returned NULL");
        return info;
    }
    guint32 arp_packets = 0;

    for (guint32 framenum = 1; framenum <= cf->count; framenum++) {
        frame_data *fdata = frame_data_sequence_find(cf->provider.frames, framenum);
        if (!fdata || fdata->file_off < 0) continue;

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
                {
                    guint32 prev_req  = info->request_count;
                    guint32 prev_repl = info->reply_count;
                    walk_arp_proto_tree(edt->tree, &ctx, 0);
                    process_arp_packet(&ctx);
                    if (info->request_count != prev_req || info->reply_count != prev_repl)
                        arp_packets++;
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
        if (err_info_str) g_free(err_info_str);
        if (framenum % 200 == 0) circle_vis_pump_events();
    }

    epan_dissect_free(edt);
    info->matched_packets = arp_packets;

    /* ---- Post-processing: generate anomaly warnings ---- */

    /* IP conflict: same IP claimed by >1 MAC in ARP replies */
    {
        GHashTableIter it;
        gpointer ip_key, mac_set_val;
        g_hash_table_iter_init(&it, ctx.ip_to_macs);
        while (g_hash_table_iter_next(&it, &ip_key, &mac_set_val)) {
            const gchar *ip    = (const gchar*)ip_key;
            GHashTable  *mset  = (GHashTable*)mac_set_val;
            guint        nmacs = g_hash_table_size(mset);
            if (nmacs > 1) {
                GList *mk = g_hash_table_get_keys(mset);
                GString *gs = g_string_new(NULL);
                for (GList *m = mk; m; m = m->next) {
                    if (gs->len > 0) g_string_append(gs, " / ");
                    g_string_append(gs, (const gchar*)m->data);
                }
                gchar *w = g_strdup_printf(
                    "IP %s claimed by %u different MACs: %s", ip, nmacs, gs->str);
                add_unique_string(&info->ip_conflict_warnings, w);
                g_free(w);
                g_list_free(mk);
                g_string_free(gs, TRUE);
            }
        }
    }

    /* Unsolicited reply: reply sender IP never seen in a request */
    {
        GHashTableIter it;
        gpointer ip_key, unused;
        g_hash_table_iter_init(&it, ctx.ip_to_macs);
        while (g_hash_table_iter_next(&it, &ip_key, &unused)) {
            const gchar *ip = (const gchar*)ip_key;
            if (!g_hash_table_lookup(ctx.requested_ips, ip)) {
                gchar *w = g_strdup_printf(
                    "ARP reply for %s — no request seen (unsolicited)", ip);
                add_unique_string(&info->unsolicited_warnings, w);
                g_free(w);
            }
        }
    }

    g_hash_table_destroy(ctx.requested_ips);
    g_hash_table_destroy(ctx.ip_to_macs);  /* also frees inner GHashTables */

    info->found = (arp_packets > 0);
    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO,
           "ARP analysis done: %u ARP pkts, %u replies, %u conflicts, %u unsolicited",
           arp_packets, info->reply_count,
           g_list_length(info->ip_conflict_warnings),
           g_list_length(info->unsolicited_warnings));
    return info;
}

/* ================================================================== */
/*  DHCP Information Extraction                                       */
/* ================================================================== */

typedef struct {
    dhcp_info_t *info;
    /* Per-packet state; reset after each packet's tree walk */
    guint8   msg_type;         /* DHCP message type 1–8, 0 = unknown */
    gchar    your_ip[64];      /* yiaddr */
    gchar    client_ip[64];    /* ciaddr */
    gchar    client_mac[64];   /* chaddr */
    gchar    server_id[64];    /* option 54 */
    gchar    hostname[256];    /* option 12 */
    gchar    domain_name[256]; /* option 15 */
    guint32  lease_secs;       /* option 51 */
    gboolean has_lease;
} dhcp_walk_ctx_t;

static void walk_dhcp_proto_tree(proto_node *node, dhcp_walk_ctx_t *ctx, int depth)
{
    if (!node || depth > 20) return;

    field_info *fi = node->finfo;
    if (fi && fi->hfinfo && fi->hfinfo->abbrev) {
        const gchar *abbrev = fi->hfinfo->abbrev;
        gchar label[ITEM_LABEL_LENGTH];
        label[0] = '\0';

        /* DHCP message type (option 53)
         * WS 4.4+: dhcp.option.dhcp  (packet-dhcp.c renamed from packet-bootp.c) */
        if (g_strcmp0(abbrev, "dhcp.option.dhcp") == 0 ||
            g_strcmp0(abbrev, "bootp.option.dhcp") == 0) {
            ctx->msg_type = (guint8)fvalue_get_uinteger(PC_FI_VALUE(fi));
        /* yiaddr: "your" / offered / assigned IP */
        } else if (g_strcmp0(abbrev, "dhcp.ip.your") == 0 ||
                   g_strcmp0(abbrev, "bootp.ip.your") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val && g_strcmp0(val, "0.0.0.0") != 0)
                g_strlcpy(ctx->your_ip, val, sizeof(ctx->your_ip));
            g_free(val);
        /* ciaddr: client IP (set in REQUEST when client has an IP) */
        } else if (g_strcmp0(abbrev, "dhcp.ip.client") == 0 ||
                   g_strcmp0(abbrev, "bootp.ip.client") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val && g_strcmp0(val, "0.0.0.0") != 0)
                g_strlcpy(ctx->client_ip, val, sizeof(ctx->client_ip));
            g_free(val);
        /* chaddr: client hardware address */
        } else if (g_strcmp0(abbrev, "dhcp.hw.mac_addr") == 0 ||
                   g_strcmp0(abbrev, "bootp.hw.mac_addr") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) g_strlcpy(ctx->client_mac, val, sizeof(ctx->client_mac));
            g_free(val);
        /* option 54: DHCP server identifier */
        } else if (g_strcmp0(abbrev, "dhcp.option.dhcp_server_id") == 0 ||
                   g_strcmp0(abbrev, "bootp.option.dhcp_server_id") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) g_strlcpy(ctx->server_id, val, sizeof(ctx->server_id));
            g_free(val);
        /* option 12: host name */
        } else if (g_strcmp0(abbrev, "dhcp.option.hostname") == 0 ||
                   g_strcmp0(abbrev, "bootp.option.hostname") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) g_strlcpy(ctx->hostname, val, sizeof(ctx->hostname));
            g_free(val);
        /* option 15: domain name */
        } else if (g_strcmp0(abbrev, "dhcp.option.domain_name") == 0 ||
                   g_strcmp0(abbrev, "bootp.option.domain_name") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) g_strlcpy(ctx->domain_name, val, sizeof(ctx->domain_name));
            g_free(val);
        /* option 3: router — add directly (may repeat for multiple gateways) */
        } else if (g_strcmp0(abbrev, "dhcp.option.router") == 0 ||
                   g_strcmp0(abbrev, "bootp.option.router") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) add_unique_string(&ctx->info->routers, val);
            g_free(val);
        /* option 6: DNS — add directly (may repeat for multiple servers) */
        } else if (g_strcmp0(abbrev, "dhcp.option.domain_name_server") == 0 ||
                   g_strcmp0(abbrev, "bootp.option.domain_name_server") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) add_unique_string(&ctx->info->dns_servers, val);
            g_free(val);
        /* option 51: lease time in seconds */
        } else if (g_strcmp0(abbrev, "dhcp.option.ip_address_lease_time") == 0 ||
                   g_strcmp0(abbrev, "bootp.option.ip_address_lease_time") == 0) {
            ctx->lease_secs = fvalue_get_uinteger(PC_FI_VALUE(fi));
            ctx->has_lease  = TRUE;
        /* option 55: parameter request list items — add directly
         * WS 4.4+: dhcp.option.request_list_item (suffix changed from param_request_list_item) */
        } else if (g_strcmp0(abbrev, "dhcp.option.request_list_item") == 0 ||
                   g_strcmp0(abbrev, "bootp.option.param_request_list_item") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) add_unique_string(&ctx->info->requested_options, val);
            g_free(val);
        }
    }

    for (proto_node *child = node->first_child; child; child = child->next)
        walk_dhcp_proto_tree(child, ctx, depth + 1);
}

/* Format a DHCP lease time (seconds) as a human-readable string. */
static gchar* format_dhcp_lease(guint32 s)
{
    if (s == 0xFFFFFFFF) return g_strdup("Infinite");
    guint32 d = s / 86400;
    guint32 h = (s % 86400) / 3600;
    guint32 m = (s % 3600) / 60;
    guint32 r = s % 60;
    if (d > 0) return g_strdup_printf("%u sec (%ud %uh %um)", s, d, h, m);
    if (h > 0) return g_strdup_printf("%u sec (%uh %um)", s, h, m);
    return g_strdup_printf("%u sec (%um %us)", s, m, r);
}

/* Process one DHCP packet after walking its tree; resets per-packet ctx state. */
static void process_dhcp_packet(dhcp_walk_ctx_t *ctx)
{
    if (ctx->msg_type != 0) {
        dhcp_info_t *info = ctx->info;

        switch (ctx->msg_type) {
            case 1: info->discover_count++; break;
            case 2: info->offer_count++;    break;
            case 3: info->request_count++;  break;
            case 4: info->decline_count++;  break;
            case 5: info->ack_count++;      break;
            case 6: info->nak_count++;      break;
            case 7: info->release_count++;  break;
            case 8: info->inform_count++;   break;
            default: break;
        }

        if (ctx->client_mac[0])   add_unique_string(&info->client_macs,   ctx->client_mac);
        if (ctx->hostname[0])     add_unique_string(&info->hostnames,      ctx->hostname);
        if (ctx->domain_name[0])  add_unique_string(&info->domain_names,   ctx->domain_name);
        if (ctx->server_id[0])    add_unique_string(&info->server_ids,     ctx->server_id);

        /* Categorise IPs by message type */
        if (ctx->msg_type == 2 && ctx->your_ip[0])
            add_unique_string(&info->offered_ips,   ctx->your_ip);
        if (ctx->msg_type == 3 && ctx->client_ip[0])
            add_unique_string(&info->requested_ips, ctx->client_ip);
        if (ctx->msg_type == 5 && ctx->your_ip[0])
            add_unique_string(&info->assigned_ips,  ctx->your_ip);

        /* Lease time */
        if (ctx->has_lease) {
            gchar *ls = format_dhcp_lease(ctx->lease_secs);
            add_unique_string(&info->lease_times, ls);
            g_free(ls);
        }
    }

    /* Reset per-packet state */
    ctx->msg_type      = 0;
    ctx->your_ip[0]    = '\0';
    ctx->client_ip[0]  = '\0';
    ctx->client_mac[0] = '\0';
    ctx->server_id[0]  = '\0';
    ctx->hostname[0]   = '\0';
    ctx->domain_name[0]= '\0';
    ctx->lease_secs    = 0;
    ctx->has_lease     = FALSE;
}

void packet_analyzer_free_dhcp_info(dhcp_info_t *info)
{
    if (!info) return;
    if (info->client_macs)      g_list_free_full(info->client_macs,      g_free);
    if (info->requested_ips)    g_list_free_full(info->requested_ips,    g_free);
    if (info->offered_ips)      g_list_free_full(info->offered_ips,      g_free);
    if (info->assigned_ips)     g_list_free_full(info->assigned_ips,     g_free);
    if (info->server_ids)       g_list_free_full(info->server_ids,       g_free);
    if (info->hostnames)        g_list_free_full(info->hostnames,        g_free);
    if (info->domain_names)     g_list_free_full(info->domain_names,     g_free);
    if (info->routers)          g_list_free_full(info->routers,          g_free);
    if (info->dns_servers)      g_list_free_full(info->dns_servers,      g_free);
    if (info->lease_times)      g_list_free_full(info->lease_times,      g_free);
    if (info->requested_options)g_list_free_full(info->requested_options,g_free);
    g_free(info);
}

dhcp_info_t* packet_analyzer_extract_dhcp_info(capture_file *cf,
                                                const gchar *addr_a,
                                                const gchar *addr_b,
                                                guint16 port,
                                                gboolean addr_is_mac)
{
    (void)addr_a; (void)addr_b; (void)port; (void)addr_is_mac; /* scan entire trace */

    dhcp_info_t *info = g_new0(dhcp_info_t, 1);
    if (!cf || cf->state != FILE_READ_DONE || !cf->provider.frames || cf->count == 0)
        return info;

    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO,
           "DHCP analysis: scanning entire trace (%u frames)", cf->count);

    dhcp_walk_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.info = info;

    epan_dissect_t *edt = epan_dissect_new(cf->epan, TRUE, TRUE);
    if (!edt) { /* WH: guard against allocation failure */
        ws_log(WS_LOG_DOMAIN, LOG_LEVEL_ERROR, "DHCP: epan_dissect_new() returned NULL");
        return info;
    }
    guint32 dhcp_packets = 0;

    for (guint32 framenum = 1; framenum <= cf->count; framenum++) {
        frame_data *fdata = frame_data_sequence_find(cf->provider.frames, framenum);
        if (!fdata || fdata->file_off < 0) continue;

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
                {
                    guint8 prev_type = ctx.msg_type;
                    walk_dhcp_proto_tree(edt->tree, &ctx, 0);
                    if (ctx.msg_type != 0 || prev_type != 0) {
                        process_dhcp_packet(&ctx);
                        dhcp_packets++;
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
        if (err_info_str) g_free(err_info_str);
        if (framenum % 200 == 0) circle_vis_pump_events();
    }

    epan_dissect_free(edt);
    info->matched_packets = dhcp_packets;
    info->found = (dhcp_packets > 0);
    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO,
           "DHCP analysis done: %u DHCP pkts, %u OFFER, %u ACK, %u NAK",
           dhcp_packets, info->offer_count, info->ack_count, info->nak_count);
    return info;
}

/* ─────────────────────────────────────────────────────────────────────────
 * DNS / DNSSEC analysis
 * ─────────────────────────────────────────────────────────────────────────*/

/* Increment a guint counter stored in a string-keyed hash table.
 * Creates the entry (count = 1) if it doesn't exist yet.          */
static void dns_hash_inc(GHashTable *ht, const gchar *key)
{
    if (!ht || !key || !*key) return;
    gpointer val = g_hash_table_lookup(ht, key);
    if (val) {
        (*(guint *)val)++;
    } else {
        guint *cnt = g_new(guint, 1);
        *cnt = 1;
        g_hash_table_insert(ht, g_strdup(key), cnt);
    }
}

/* Return a heap-allocated string for a DNS RR type number.
 * Caller must g_free() the result.                                */
static gchar *dns_type_str(guint16 type)
{
    switch (type) {
        case   1: return g_strdup("A");
        case   2: return g_strdup("NS");
        case   5: return g_strdup("CNAME");
        case   6: return g_strdup("SOA");
        case  12: return g_strdup("PTR");
        case  15: return g_strdup("MX");
        case  16: return g_strdup("TXT");
        case  28: return g_strdup("AAAA");
        case  33: return g_strdup("SRV");
        case  43: return g_strdup("DS");
        case  46: return g_strdup("RRSIG");
        case  48: return g_strdup("DNSKEY");
        case  52: return g_strdup("TLSA");
        case  65: return g_strdup("HTTPS");
        case 255: return g_strdup("ANY");
        case 257: return g_strdup("CAA");
        default:  return g_strdup_printf("TYPE%u", (unsigned)type);
    }
}

typedef struct _dns_walk_ctx {
    dns_info_t *info;
    /* per-packet state — reset before each frame */
    gboolean is_response;
    gboolean recursion_desired;
    guint8   rcode;
    gboolean has_response_flag;
    /* current query RR being assembled */
    char     qry_name[256];
    /* current answer RR name and type (set before the value field) */
    char     ans_name[256];
    char     ans_type_str[32];
    /* all query names seen in this packet — for NXDOMAIN tracking */
    GList   *pkt_qry_names;
} dns_walk_ctx_t;

static void walk_dns_proto_tree(proto_node *node, dns_walk_ctx_t *ctx, int depth)
{
    if (!node || depth > 25) return;

    field_info *fi = node->finfo;
    if (fi && fi->hfinfo && fi->hfinfo->abbrev) {
        const gchar *abbrev = fi->hfinfo->abbrev;
        gchar label[ITEM_LABEL_LENGTH];
        label[0] = '\0';

        /* ── Packet-level DNS flags ─────────────────────────────── */
        if (g_strcmp0(abbrev, "dns.flags.response") == 0) {
            ctx->is_response       = (fvalue_get_uinteger(PC_FI_VALUE(fi)) != 0);
            ctx->has_response_flag = TRUE;
        } else if (g_strcmp0(abbrev, "dns.flags.rcode") == 0) {
            ctx->rcode = (guint8)fvalue_get_uinteger(PC_FI_VALUE(fi));
        } else if (g_strcmp0(abbrev, "dns.flags.recdesired") == 0) {
            if (fvalue_get_uinteger(PC_FI_VALUE(fi)))
                ctx->recursion_desired = TRUE;

        /* ── Query section ──────────────────────────────────────── */
        } else if (g_strcmp0(abbrev, "dns.qry.name") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val)
                g_strlcpy(ctx->qry_name, val, sizeof(ctx->qry_name));
            g_free(val);

        } else if (g_strcmp0(abbrev, "dns.qry.type") == 0) {
            guint16 qtype = (guint16)fvalue_get_uinteger(PC_FI_VALUE(fi));
            if (ctx->qry_name[0]) {
                dns_hash_inc(ctx->info->name_counts, ctx->qry_name);
                ctx->pkt_qry_names = g_list_append(ctx->pkt_qry_names,
                                                    g_strdup(ctx->qry_name));
                ctx->qry_name[0] = '\0';
            }
            gchar *tstr = dns_type_str(qtype);
            dns_hash_inc(ctx->info->type_counts, tstr);
            g_free(tstr);

        /* ── Answer RR — name and type come before the value ───── */
        } else if (g_strcmp0(abbrev, "dns.resp.name") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val)
                g_strlcpy(ctx->ans_name, val, sizeof(ctx->ans_name));
            g_free(val);

        } else if (g_strcmp0(abbrev, "dns.resp.type") == 0) {
            guint16 atype = (guint16)fvalue_get_uinteger(PC_FI_VALUE(fi));
            gchar *tstr = dns_type_str(atype);
            g_strlcpy(ctx->ans_type_str, tstr, sizeof(ctx->ans_type_str));
            g_free(tstr);

        /* ── Answer RR values — emit entry when value seen ─────── */
        } else if (g_strcmp0(abbrev, "dns.a") == 0 && ctx->ans_name[0]) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) {
                gchar *e = g_strdup_printf("%s %s %s", ctx->ans_name,
                    ctx->ans_type_str[0] ? ctx->ans_type_str : "A", val);
                add_unique_string(&ctx->info->answers, e);
                g_free(e);
                ctx->ans_name[0] = '\0'; ctx->ans_type_str[0] = '\0';
            }
            g_free(val);

        } else if (g_strcmp0(abbrev, "dns.aaaa") == 0 && ctx->ans_name[0]) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) {
                gchar *e = g_strdup_printf("%s %s %s", ctx->ans_name,
                    ctx->ans_type_str[0] ? ctx->ans_type_str : "AAAA", val);
                add_unique_string(&ctx->info->answers, e);
                g_free(e);
                ctx->ans_name[0] = '\0'; ctx->ans_type_str[0] = '\0';
            }
            g_free(val);

        } else if (g_strcmp0(abbrev, "dns.cname") == 0 && ctx->ans_name[0]) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) {
                gchar *e = g_strdup_printf("%s CNAME %s", ctx->ans_name, val);
                add_unique_string(&ctx->info->answers, e);
                g_free(e);
                ctx->ans_name[0] = '\0'; ctx->ans_type_str[0] = '\0';
            }
            g_free(val);

        } else if (g_strcmp0(abbrev, "dns.mx.mail_exchange") == 0 && ctx->ans_name[0]) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) {
                gchar *e = g_strdup_printf("%s MX %s", ctx->ans_name, val);
                add_unique_string(&ctx->info->answers, e);
                g_free(e);
                ctx->ans_name[0] = '\0'; ctx->ans_type_str[0] = '\0';
            }
            g_free(val);

        } else if (g_strcmp0(abbrev, "dns.ns") == 0 && ctx->ans_name[0]) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) {
                gchar *e = g_strdup_printf("%s NS %s", ctx->ans_name, val);
                add_unique_string(&ctx->info->answers, e);
                g_free(e);
                ctx->ans_name[0] = '\0'; ctx->ans_type_str[0] = '\0';
            }
            g_free(val);

        } else if (g_strcmp0(abbrev, "dns.ptr.domain_name") == 0 && ctx->ans_name[0]) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) {
                gchar *e = g_strdup_printf("%s PTR %s", ctx->ans_name, val);
                add_unique_string(&ctx->info->answers, e);
                g_free(e);
                ctx->ans_name[0] = '\0'; ctx->ans_type_str[0] = '\0';
            }
            g_free(val);

        } else if (g_strcmp0(abbrev, "dns.srv.name") == 0 && ctx->ans_name[0]) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) {
                gchar *e = g_strdup_printf("%s SRV %s", ctx->ans_name, val);
                add_unique_string(&ctx->info->answers, e);
                g_free(e);
                ctx->ans_name[0] = '\0'; ctx->ans_type_str[0] = '\0';
            }
            g_free(val);

        } else if (g_strcmp0(abbrev, "dns.txt") == 0 && ctx->ans_name[0]) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) {
                gchar *e = g_strdup_printf("%s TXT \"%s\"", ctx->ans_name, val);
                add_unique_string(&ctx->info->answers, e);
                g_free(e);
                ctx->ans_name[0] = '\0'; ctx->ans_type_str[0] = '\0';
            }
            g_free(val);

        } else if (g_strcmp0(abbrev, "dns.soa.mname") == 0 && ctx->ans_name[0]) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) {
                gchar *e = g_strdup_printf("%s SOA %s", ctx->ans_name, val);
                add_unique_string(&ctx->info->answers, e);
                g_free(e);
                ctx->ans_name[0] = '\0'; ctx->ans_type_str[0] = '\0';
            }
            g_free(val);

        } else if (g_strcmp0(abbrev, "dns.caa.value") == 0 && ctx->ans_name[0]) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) {
                gchar *e = g_strdup_printf("%s CAA %s", ctx->ans_name, val);
                add_unique_string(&ctx->info->answers, e);
                g_free(e);
                ctx->ans_name[0] = '\0'; ctx->ans_type_str[0] = '\0';
            }
            g_free(val);
        }
    }

    for (proto_node *child = node->first_child; child; child = child->next)
        walk_dns_proto_tree(child, ctx, depth + 1);
}

static void reset_dns_ctx(dns_walk_ctx_t *ctx)
{
    g_list_free_full(ctx->pkt_qry_names, g_free);
    ctx->pkt_qry_names     = NULL;
    ctx->is_response       = FALSE;
    ctx->recursion_desired = FALSE;
    ctx->rcode             = 0;
    ctx->has_response_flag = FALSE;
    ctx->qry_name[0]       = '\0';
    ctx->ans_name[0]       = '\0';
    ctx->ans_type_str[0]   = '\0';
}

static void process_dns_packet(dns_walk_ctx_t *ctx)
{
    dns_info_t *info = ctx->info;

    if (ctx->is_response) {
        info->response_count++;
        switch (ctx->rcode) {
            case 0: info->noerror_count++;  break;
            case 2: info->servfail_count++; break;
            case 3:
                info->nxdomain_count++;
                for (GList *l = ctx->pkt_qry_names; l; l = l->next)
                    if (l->data) add_unique_string(&info->nxdomain_names, (gchar *)l->data);
                break;
            case 5: info->refused_count++;  break;
            default: info->other_error_count++; break;
        }
    } else {
        info->query_count++;
        if (ctx->recursion_desired)
            info->uses_recursion = TRUE;
    }
    reset_dns_ctx(ctx);
}

void packet_analyzer_free_dns_info(dns_info_t *info)
{
    if (!info) return;
    if (info->type_counts)    g_hash_table_destroy(info->type_counts);
    if (info->name_counts)    g_hash_table_destroy(info->name_counts);
    if (info->answers)        g_list_free_full(info->answers,        g_free);
    if (info->nxdomain_names) g_list_free_full(info->nxdomain_names, g_free);
    g_free(info);
}

dns_info_t* packet_analyzer_extract_dns_info(capture_file *cf,
                                              const gchar *addr_a,
                                              const gchar *addr_b,
                                              guint16 port,
                                              gboolean addr_is_mac)
{
    dns_info_t *info = g_new0(dns_info_t, 1);
    info->type_counts = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
    info->name_counts = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);

    if (!cf || cf->state != FILE_READ_DONE || !cf->provider.frames || cf->count == 0)
        return info;

    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO,
           "DNS analysis: addr_a=%s addr_b=%s port=%u is_mac=%d (%u frames)",
           addr_a ? addr_a : "?", addr_b ? addr_b : "?", port, addr_is_mac, cf->count);

    dns_walk_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.info = info;

    epan_dissect_t *edt = epan_dissect_new(cf->epan, TRUE, TRUE);
    if (!edt) {
        ws_log(WS_LOG_DOMAIN, LOG_LEVEL_ERROR, "DNS: epan_dissect_new() returned NULL");
        return info;
    }
    guint32 dns_packets = 0;

    for (guint32 framenum = 1; framenum <= cf->count; framenum++) {
        frame_data *fdata = frame_data_sequence_find(cf->provider.frames, framenum);
        if (!fdata || fdata->file_off < 0) continue;

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
                /* Filter to the selected pair (addresses + port) */
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
                        walk_dns_proto_tree(edt->tree, &ctx, 0);
                        if (ctx.has_response_flag) {
                            process_dns_packet(&ctx);
                            dns_packets++;
                        } else {
                            reset_dns_ctx(&ctx);
                        }
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
        if (err_info_str) g_free(err_info_str);
        if (framenum % 200 == 0) circle_vis_pump_events();
    }

    epan_dissect_free(edt);
    info->matched_packets = dns_packets;
    info->found = (dns_packets > 0);
    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO,
           "DNS analysis done: %u DNS pkts, %u queries, %u responses, %u NXDOMAIN",
           dns_packets, info->query_count, info->response_count, info->nxdomain_count);
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

/* ─────────────────────────────────────────────────────────────────────────────
 * ICMP / ICMPv6 type+code extraction
 * ───────────────────────────────────────────────────────────────────────────── */

static const gchar *icmp_type_name(guint8 type)
{
    switch (type) {
        case  0: return "Echo Reply";
        case  3: return "Destination Unreachable";
        case  4: return "Source Quench";
        case  5: return "Redirect";
        case  8: return "Echo Request";
        case  9: return "Router Advertisement";
        case 10: return "Router Solicitation";
        case 11: return "Time Exceeded";
        case 12: return "Parameter Problem";
        case 13: return "Timestamp Request";
        case 14: return "Timestamp Reply";
        case 15: return "Information Request";
        case 16: return "Information Reply";
        case 17: return "Address Mask Request";
        case 18: return "Address Mask Reply";
        case 30: return "Traceroute";
        default: return NULL;
    }
}

static const gchar *icmpv6_type_name(guint8 type)
{
    switch (type) {
        case   1: return "Destination Unreachable";
        case   2: return "Packet Too Big";
        case   3: return "Time Exceeded";
        case   4: return "Parameter Problem";
        case 128: return "Echo Request";
        case 129: return "Echo Reply";
        case 130: return "Multicast Listener Query";
        case 131: return "Multicast Listener Report";
        case 132: return "Multicast Listener Done";
        case 133: return "Router Solicitation";
        case 134: return "Router Advertisement";
        case 135: return "Neighbor Solicitation";
        case 136: return "Neighbor Advertisement";
        case 137: return "Redirect";
        case 143: return "MLDv2 Report";
        default:  return NULL;
    }
}

/* Walk one frame's proto tree, extract icmp.type / icmpv6.type and count */
static void walk_icmp_proto_tree(proto_tree *node, icmp_info_t *info, int depth)
{
    if (!node || depth > 20) return;

    field_info *fi = node->finfo;
    if (fi && fi->hfinfo && fi->hfinfo->abbrev) {
        const gchar *abbrev = fi->hfinfo->abbrev;
        gboolean is_icmp_type   = (g_strcmp0(abbrev, "icmp.type")   == 0);
        gboolean is_icmpv6_type = (g_strcmp0(abbrev, "icmpv6.type") == 0);

        if (is_icmp_type || is_icmpv6_type) {
            guint8 type_val = (guint8)fvalue_get_uinteger(PC_FI_VALUE(fi));
            const gchar *tname = info->is_v6
                                 ? icmpv6_type_name(type_val)
                                 : icmp_type_name(type_val);
            gchar label[64];
            if (tname)
                g_snprintf(label, sizeof(label), "Type %u — %s", (unsigned)type_val, tname);
            else
                g_snprintf(label, sizeof(label), "Type %u", (unsigned)type_val);

            /* WH: Fixed memory leak — the old g_hash_table_replace() branch allocated
             * a new key string with g_strdup(label) but type_labels still pointed to the
             * original allocation, so both the new string leaked AND type_labels held a
             * stale pointer once the hash table freed the old key on replace.
             * Fix: g_hash_table_steal() removes the entry without invoking key_destroy,
             * then we re-insert with the SAME key pointer and the updated count — no new
             * allocation needed, and type_labels stays valid throughout.              */
            gpointer existing_key = NULL;
            gpointer existing_val = NULL;
            if (g_hash_table_lookup_extended(info->type_counts, label,
                                             &existing_key, &existing_val)) {
                /* Key already present — steal and re-insert with same key, no new alloc */
                g_hash_table_steal(info->type_counts, label);
                guint count = GPOINTER_TO_UINT(existing_val) + 1;
                g_hash_table_insert(info->type_counts, existing_key, GUINT_TO_POINTER(count));
            } else {
                gchar *k = g_strdup(label);
                g_hash_table_insert(info->type_counts, k, GUINT_TO_POINTER(1));
                info->type_labels = g_list_append(info->type_labels, k);
            }
            info->matched_packets++;
            return; /* done for this frame — one type per ICMP frame */
        }
    }

    proto_tree *child = node->first_child;
    while (child) {
        walk_icmp_proto_tree(child, info, depth + 1);
        child = child->next;
    }
}

icmp_info_t* packet_analyzer_extract_icmp_info(capture_file *cf,
                                                const gchar *src_addr,
                                                const gchar *dst_addr,
                                                gboolean addr_is_mac,
                                                gboolean is_v6)
{
    icmp_info_t *info = g_new0(icmp_info_t, 1);
    info->is_v6       = is_v6;
    info->type_counts = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
    info->type_labels = NULL;

    if (!cf || cf->state != FILE_READ_DONE || !cf->provider.frames || cf->count == 0)
        return info;

    const gchar *proto_filter = is_v6 ? "icmpv6" : "icmp";
    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO,
           "ICMP analysis: scanning %u frames for %s between %s and %s",
           cf->count, proto_filter,
           src_addr ? src_addr : "(any)", dst_addr ? dst_addr : "(any)");

    epan_dissect_t *edt = epan_dissect_new(cf->epan, TRUE, TRUE);
    if (!edt) { /* WH: guard against allocation failure */
        ws_log(WS_LOG_DOMAIN, LOG_LEVEL_ERROR, "ICMP: epan_dissect_new() returned NULL");
        return info;
    }

    for (guint32 framenum = 1; framenum <= cf->count; framenum++) {
        frame_data *fdata = frame_data_sequence_find(cf->provider.frames, framenum);
        if (!fdata || fdata->file_off < 0) continue;

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
                /* Filter: must contain the right ICMP protocol */
                if (edt->tree && proto_is_frame_protocol(edt->pi.layers, proto_filter)) {
                    /* Filter by address pair if provided */
                    gboolean addr_match = TRUE;
                    if (src_addr && dst_addr) {
                        packet_info *pinfo = &edt->pi;
                        const gchar *frame_src = addr_is_mac
                            ? address_to_str(wmem_epan_scope(), &pinfo->dl_src)
                            : address_to_str(wmem_epan_scope(), &pinfo->net_src);
                        const gchar *frame_dst = addr_is_mac
                            ? address_to_str(wmem_epan_scope(), &pinfo->dl_dst)
                            : address_to_str(wmem_epan_scope(), &pinfo->net_dst);
                        addr_match = (frame_src && frame_dst) &&
                            ((g_strcmp0(frame_src, src_addr) == 0 && g_strcmp0(frame_dst, dst_addr) == 0) ||
                             (g_strcmp0(frame_src, dst_addr) == 0 && g_strcmp0(frame_dst, src_addr) == 0));
                    }
                    if (addr_match)
                        walk_icmp_proto_tree(edt->tree, info, 0);
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
        if (err_info_str) g_free(err_info_str);
        if (framenum % 500 == 0) circle_vis_pump_events();
    }

    epan_dissect_free(edt);
    info->found = (info->matched_packets > 0);
    return info;
}

void packet_analyzer_free_icmp_info(icmp_info_t *info)
{
    if (!info) return;
    if (info->type_counts) g_hash_table_destroy(info->type_counts);
    if (info->type_labels)  g_list_free(info->type_labels);  /* strings owned by hash table */
    g_free(info);
}

/* ================================================================== */
/*  LDAP Information Extraction                                       */
/* ================================================================== */

static const gchar *ldap_result_code_name(guint32 code)
{
    switch (code) {
        case  0: return "success";
        case  1: return "operationsError";
        case  2: return "protocolError";
        case  3: return "timeLimitExceeded";
        case  4: return "sizeLimitExceeded";
        case  7: return "authMethodNotSupported";
        case  8: return "strongerAuthRequired";
        case 10: return "referral";
        case 11: return "adminLimitExceeded";
        case 13: return "confidentialityRequired";
        case 14: return "saslBindInProgress";
        case 16: return "noSuchAttribute";
        case 32: return "noSuchObject";
        case 48: return "inappropriateAuthentication";
        case 49: return "invalidCredentials";
        case 50: return "insufficientAccessRights";
        case 51: return "busy";
        case 52: return "unavailable";
        case 53: return "unwillingToPerform";
        case 65: return "objectClassViolation";
        case 68: return "entryAlreadyExists";
        case 80: return "other";
        default: return NULL;
    }
}

static void ldap_hash_inc(GHashTable *ht, const gchar *key)
{
    if (!ht || !key || !*key) return;
    gpointer val = g_hash_table_lookup(ht, key);
    if (val) {
        (*(guint *)val)++;
    } else {
        guint *cnt = g_new(guint, 1);
        *cnt = 1;
        g_hash_table_insert(ht, g_strdup(key), cnt);
    }
}

typedef struct {
    ldap_info_t *info;
    /* Per-frame accumulators — reset after processing each frame */
    gboolean saw_base_object;    /* SearchRequest */
    gboolean saw_bind_name;      /* BindRequest name field */
    gboolean saw_bind_simple;    /* simple auth credential field */
    gboolean saw_sasl;           /* SASL mechanism field */
    gboolean saw_result_code;    /* any LDAPResult */
    gboolean saw_search_entry;   /* SearchResultEntry object name */
    gboolean saw_modify;         /* ModifyRequest / ModDNRequest */
    gboolean saw_add;            /* AddRequest */
    gboolean saw_delete;         /* DelRequest */
    gchar    bind_dn[512];
    gchar    sasl_mech[64];
    gchar    base_dn[512];
    gchar    search_filter[256];
    guint32  result_code;
    gboolean has_result_code;
} ldap_walk_ctx_t;

static void walk_ldap_proto_tree(proto_node *node, ldap_walk_ctx_t *ctx, int depth)
{
    if (!node || depth > 30) return;

    field_info *fi = node->finfo;
    if (fi && fi->hfinfo && fi->hfinfo->abbrev) {
        const gchar *abbrev = fi->hfinfo->abbrev;
        gchar label[ITEM_LABEL_LENGTH];
        label[0] = '\0';

        /* SearchRequest base DN — presence marks this as a search */
        if (g_strcmp0(abbrev, "ldap.baseObject") == 0) {
            ctx->saw_base_object = TRUE;
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val)
                g_strlcpy(ctx->base_dn, val, sizeof(ctx->base_dn));
            g_free(val);

        /* BindRequest name (DN) — two possible abbrev spellings across WS versions */
        } else if (g_strcmp0(abbrev, "ldap.bindRequest_name") == 0 ||
                   g_strcmp0(abbrev, "ldap.name") == 0) {
            ctx->saw_bind_name = TRUE;
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val)
                g_strlcpy(ctx->bind_dn, val, sizeof(ctx->bind_dn));
            g_free(val);

        /* Simple authentication credential — confirms simple/anonymous bind */
        } else if (g_strcmp0(abbrev, "ldap.simple") == 0 ||
                   g_strcmp0(abbrev, "ldap.bind_simple") == 0) {
            ctx->saw_bind_simple = TRUE;

        /* SASL mechanism — confirms SASL bind */
        } else if (g_strcmp0(abbrev, "ldap.mechanism") == 0) {
            ctx->saw_sasl = TRUE;
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val)
                g_strlcpy(ctx->sasl_mech, val, sizeof(ctx->sasl_mech));
            g_free(val);

        /* Search filter — both abbrev spellings seen in different WS builds */
        } else if (g_strcmp0(abbrev, "ldap.filter") == 0 ||
                   g_strcmp0(abbrev, "ldap.Filter") == 0) {
            if (ctx->search_filter[0] == '\0') {
                fill_label_compat(fi, label);
                gchar *val = label_value(label);
                if (val && *val)
                    g_strlcpy(ctx->search_filter, val, sizeof(ctx->search_filter));
                g_free(val);
            }

        /* Any LDAPResult resultCode field */
        } else if (g_strcmp0(abbrev, "ldap.resultCode") == 0) {
            ctx->result_code     = fvalue_get_uinteger(PC_FI_VALUE(fi));
            ctx->saw_result_code = TRUE;
            ctx->has_result_code = TRUE;

        /* SearchResultEntry objectName — counts individual entries returned */
        } else if (g_strcmp0(abbrev, "ldap.searchResEntry_objectName") == 0 ||
                   g_strcmp0(abbrev, "ldap.objectName") == 0) {
            ctx->saw_search_entry = TRUE;

        /* ModifyRequest / ModDNRequest object DN */
        } else if (g_strcmp0(abbrev, "ldap.modifyRequest_object") == 0 ||
                   g_strcmp0(abbrev, "ldap.modifyDNRequest_entry") == 0) {
            ctx->saw_modify = TRUE;

        /* AddRequest entry DN */
        } else if (g_strcmp0(abbrev, "ldap.addRequest_entry") == 0) {
            ctx->saw_add = TRUE;

        /* DelRequest DN */
        } else if (g_strcmp0(abbrev, "ldap.delRequest") == 0 ||
                   g_strcmp0(abbrev, "ldap.delete_request") == 0) {
            ctx->saw_delete = TRUE;
        }
    }

    for (proto_node *child = node->first_child; child; child = child->next)
        walk_ldap_proto_tree(child, ctx, depth + 1);
}

static void process_ldap_frame(ldap_walk_ctx_t *ctx)
{
    ldap_info_t *info = ctx->info;

    /* SearchRequest */
    if (ctx->saw_base_object) {
        info->search_count++;
        add_unique_string(&info->base_dns,
                          ctx->base_dn[0] ? ctx->base_dn : "(root)");
        if (ctx->search_filter[0] && g_list_length(info->search_filters) < 30)
            add_unique_string(&info->search_filters, ctx->search_filter);
    }

    /* SearchResultEntry */
    if (ctx->saw_search_entry)
        info->search_res_entry_count++;

    /* BindRequest */
    if (ctx->saw_bind_name || ctx->saw_bind_simple || ctx->saw_sasl) {
        info->bind_count++;
        if (ctx->saw_sasl) {
            info->has_sasl_bind = TRUE;
            if (ctx->sasl_mech[0])
                add_unique_string(&info->sasl_mechanisms, ctx->sasl_mech);
        } else {
            info->has_simple_bind = TRUE;
            if (ctx->bind_dn[0])
                add_unique_string(&info->bind_dns, ctx->bind_dn);
            else
                info->has_anonymous_bind = TRUE;
        }
    }

    if (ctx->saw_modify) info->modify_count++;
    if (ctx->saw_add)    info->add_count++;
    if (ctx->saw_delete) info->delete_count++;

    /* Result code — track per-code counts */
    if (ctx->has_result_code) {
        const gchar *code_name = ldap_result_code_name(ctx->result_code);
        gchar code_str[48];
        if (code_name)
            g_snprintf(code_str, sizeof(code_str), "%s", code_name);
        else
            g_snprintf(code_str, sizeof(code_str), "code %u", ctx->result_code);
        ldap_hash_inc(info->result_counts, code_str);
        if (ctx->result_code == 0)
            info->success_count++;
        else
            info->error_count++;
    }

    /* Reset per-frame state */
    memset(ctx, 0, sizeof(*ctx));
    ctx->info = info;
}

void packet_analyzer_free_ldap_info(ldap_info_t *info)
{
    if (!info) return;
    if (info->bind_dns)        g_list_free_full(info->bind_dns,       g_free);
    if (info->sasl_mechanisms) g_list_free_full(info->sasl_mechanisms, g_free);
    if (info->base_dns)        g_list_free_full(info->base_dns,        g_free);
    if (info->search_filters)  g_list_free_full(info->search_filters,  g_free);
    if (info->result_counts)   g_hash_table_destroy(info->result_counts);
    g_free(info);
}

ldap_info_t* packet_analyzer_extract_ldap_info(capture_file *cf,
                                                const gchar *addr_a,
                                                const gchar *addr_b,
                                                guint16 port,
                                                gboolean addr_is_mac)
{
    ldap_info_t *info = g_new0(ldap_info_t, 1);
    info->result_counts = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
    info->is_tls = (port == 636 || port == 3269);

    if (!cf || cf->state != FILE_READ_DONE || !cf->provider.frames || cf->count == 0)
        return info;

    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO,
           "LDAP analysis: addr_a=%s addr_b=%s port=%u is_mac=%d (%u frames)",
           addr_a ? addr_a : "?", addr_b ? addr_b : "?", port, addr_is_mac, cf->count);

    ldap_walk_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.info = info;

    epan_dissect_t *edt = epan_dissect_new(cf->epan, TRUE, TRUE);
    if (!edt) {
        ws_log(WS_LOG_DOMAIN, LOG_LEVEL_ERROR, "LDAP: epan_dissect_new() returned NULL");
        return info;
    }
    guint32 ldap_packets = 0;

    for (guint32 framenum = 1; framenum <= cf->count; framenum++) {
        frame_data *fdata = frame_data_sequence_find(cf->provider.frames, framenum);
        if (!fdata || fdata->file_off < 0) continue;

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
                        walk_ldap_proto_tree(edt->tree, &ctx, 0);
                        gboolean any_ldap =
                            ctx.saw_base_object || ctx.saw_bind_name ||
                            ctx.saw_bind_simple  || ctx.saw_sasl     ||
                            ctx.has_result_code  || ctx.saw_search_entry ||
                            ctx.saw_modify || ctx.saw_add || ctx.saw_delete;
                        if (any_ldap) {
                            process_ldap_frame(&ctx);
                            ldap_packets++;
                        } else {
                            /* No LDAP fields in this frame; reset without counting */
                            memset(&ctx, 0, sizeof(ctx));
                            ctx.info = info;
                        }
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
        if (err_info_str) g_free(err_info_str);
        if (framenum % 200 == 0) circle_vis_pump_events();
    }

    epan_dissect_free(edt);
    info->matched_packets = ldap_packets;
    info->found = (ldap_packets > 0);
    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO,
           "LDAP analysis done: %u LDAP pkts, %u binds, %u searches, %u entries",
           ldap_packets, info->bind_count, info->search_count, info->search_res_entry_count);
    return info;
}

/* ================================================================== */
/*  SNMP Information Extraction                                       */
/* ================================================================== */

/* Map BER context tag (0xa0-0xa8) or 0-indexed value to PDU type name */
static const gchar *snmp_pdu_type_name(guint32 t)
{
    if (t >= 160) t -= 160;   /* normalize BER tag to 0-indexed */
    switch (t) {
        case 0: return "GetRequest";
        case 1: return "GetNextRequest";
        case 2: return "Response";
        case 3: return "SetRequest";
        case 4: return "Trap (v1)";
        case 5: return "GetBulkRequest";
        case 6: return "InformRequest";
        case 7: return "Trap (v2/v3)";
        case 8: return "Report";
        default: return NULL;
    }
}

static const gchar *snmp_error_status_name(guint32 s)
{
    switch (s) {
        case  0: return "noError";
        case  1: return "tooBig";
        case  2: return "noSuchName";
        case  3: return "badValue";
        case  4: return "readOnly";
        case  5: return "genErr";
        case  6: return "noAccess";
        case  7: return "wrongType";
        case  8: return "wrongLength";
        case  9: return "wrongEncoding";
        case 10: return "wrongValue";
        case 11: return "noCreation";
        case 12: return "inconsistentValue";
        case 13: return "resourceUnavailable";
        case 14: return "commitFailed";
        case 15: return "undoFailed";
        case 16: return "authorizationError";
        case 17: return "notWritable";
        case 18: return "inconsistentName";
        default: return NULL;
    }
}

static void snmp_hash_inc(GHashTable *ht, const gchar *key)
{
    if (!ht || !key || !*key) return;
    gpointer val = g_hash_table_lookup(ht, key);
    if (val) { (*(guint *)val)++; }
    else {
        guint *cnt = g_new(guint, 1); *cnt = 1;
        g_hash_table_insert(ht, g_strdup(key), cnt);
    }
}

typedef struct {
    snmp_info_t *info;
    /* Per-frame state */
    guint32  version;
    gboolean has_version;
    guint32  pdu_type;         /* BER tag 0xa0-0xa8, or 0-indexed 0-8 */
    gboolean has_pdu_type;
    guint32  error_status;
    gboolean has_error_status;
    gchar    community[256];
    gboolean has_community;
    gchar    username[256];    /* v3 USM userName */
    gboolean has_username;
} snmp_walk_ctx_t;

static void walk_snmp_proto_tree(proto_node *node, snmp_walk_ctx_t *ctx, int depth)
{
    if (!node || depth > 30) return;

    field_info *fi = node->finfo;
    if (fi && fi->hfinfo && fi->hfinfo->abbrev) {
        const gchar *abbrev = fi->hfinfo->abbrev;
        gchar label[ITEM_LABEL_LENGTH];
        label[0] = '\0';

        /* SNMP version (0=v1, 1=v2c, 3=v3) */
        if (g_strcmp0(abbrev, "snmp.version") == 0) {
            ctx->version     = fvalue_get_uinteger(PC_FI_VALUE(fi));
            ctx->has_version = TRUE;

        /* PDU type — BER context tag (0xa0-0xa8) */
        } else if (g_strcmp0(abbrev, "snmp.type") == 0 ||
                   g_strcmp0(abbrev, "snmp.pdu_type") == 0) {
            ctx->pdu_type     = fvalue_get_uinteger(PC_FI_VALUE(fi));
            ctx->has_pdu_type = TRUE;

        /* Community string (v1/v2c) */
        } else if (g_strcmp0(abbrev, "snmp.community") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) {
                g_strlcpy(ctx->community, val, sizeof(ctx->community));
                ctx->has_community = TRUE;
            }
            g_free(val);

        /* v3 USM username — multiple field name spellings across WS versions */
        } else if (g_strcmp0(abbrev, "snmp.msgUserName")  == 0 ||
                   g_strcmp0(abbrev, "snmp.v3.userName")  == 0  ||
                   g_strcmp0(abbrev, "snmp.usmUserName")  == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) {
                g_strlcpy(ctx->username, val, sizeof(ctx->username));
                ctx->has_username = TRUE;
            }
            g_free(val);

        /* Variable binding OID — appears once per varbind, cap unique OIDs at 100 */
        } else if (g_strcmp0(abbrev, "snmp.name") == 0) {
            if (g_hash_table_size(ctx->info->oid_counts) < 100) {
                fill_label_compat(fi, label);
                gchar *val = label_value(label);
                if (val && *val)
                    snmp_hash_inc(ctx->info->oid_counts, val);
                g_free(val);
            }

        /* Error status — only count non-zero values */
        } else if (g_strcmp0(abbrev, "snmp.error_status") == 0 ||
                   g_strcmp0(abbrev, "snmp.error-status") == 0) {
            guint32 es = fvalue_get_uinteger(PC_FI_VALUE(fi));
            if (es > 0) {
                ctx->error_status     = es;
                ctx->has_error_status = TRUE;
            }
        }
    }

    for (proto_node *child = node->first_child; child; child = child->next)
        walk_snmp_proto_tree(child, ctx, depth + 1);
}

static void process_snmp_frame(snmp_walk_ctx_t *ctx)
{
    snmp_info_t *info = ctx->info;

    if (ctx->has_version) {
        switch (ctx->version) {
            case 0: info->v1_count++;  break;
            case 1: info->v2c_count++; break;
            case 3: info->v3_count++;  break;
            default: break;
        }
    }

    if (ctx->has_pdu_type) {
        const gchar *pname = snmp_pdu_type_name(ctx->pdu_type);
        if (pname) {
            snmp_hash_inc(info->pdu_counts, pname);
            guint32 t = ctx->pdu_type;
            if (t >= 160) t -= 160;
            switch (t) {
                case 0: case 1: case 5: info->get_count++;      break;
                case 2:                 info->response_count++;  break;
                case 3:                 info->set_count++;       break;
                case 4: case 7:         info->trap_count++;      break;
                case 6:                 info->inform_count++;    break;
                case 8:                 info->report_count++;    break;
                default: break;
            }
        }
    }

    if (ctx->has_community) {
        add_unique_string(&info->communities, ctx->community);
        if (g_strcmp0(ctx->community, "public")  == 0 ||
            g_strcmp0(ctx->community, "private") == 0)
            info->has_default_community = TRUE;
    }

    if (ctx->has_username)
        add_unique_string(&info->v3_usernames, ctx->username);

    if (ctx->has_error_status) {
        info->error_total++;
        const gchar *ename = snmp_error_status_name(ctx->error_status);
        gchar ebuf[32];
        if (ename) g_snprintf(ebuf, sizeof(ebuf), "%s", ename);
        else       g_snprintf(ebuf, sizeof(ebuf), "error %u", ctx->error_status);
        snmp_hash_inc(info->error_counts, ebuf);
    }

    memset(ctx, 0, sizeof(*ctx));
    ctx->info = info;
}

void packet_analyzer_free_snmp_info(snmp_info_t *info)
{
    if (!info) return;
    if (info->pdu_counts)   g_hash_table_destroy(info->pdu_counts);
    if (info->communities)  g_list_free_full(info->communities,  g_free);
    if (info->v3_usernames) g_list_free_full(info->v3_usernames, g_free);
    if (info->oid_counts)   g_hash_table_destroy(info->oid_counts);
    if (info->error_counts) g_hash_table_destroy(info->error_counts);
    g_free(info);
}

snmp_info_t* packet_analyzer_extract_snmp_info(capture_file *cf,
                                                const gchar *addr_a,
                                                const gchar *addr_b,
                                                guint16 port,
                                                gboolean addr_is_mac)
{
    snmp_info_t *info = g_new0(snmp_info_t, 1);
    info->pdu_counts   = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
    info->oid_counts   = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
    info->error_counts = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);

    if (!cf || cf->state != FILE_READ_DONE || !cf->provider.frames || cf->count == 0)
        return info;

    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO,
           "SNMP analysis: addr_a=%s addr_b=%s port=%u (%u frames)",
           addr_a ? addr_a : "?", addr_b ? addr_b : "?", port, cf->count);

    snmp_walk_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.info = info;

    epan_dissect_t *edt = epan_dissect_new(cf->epan, TRUE, TRUE);
    if (!edt) {
        ws_log(WS_LOG_DOMAIN, LOG_LEVEL_ERROR, "SNMP: epan_dissect_new() returned NULL");
        return info;
    }
    guint32 snmp_packets = 0;

    for (guint32 framenum = 1; framenum <= cf->count; framenum++) {
        frame_data *fdata = frame_data_sequence_find(cf->provider.frames, framenum);
        if (!fdata || fdata->file_off < 0) continue;

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
                        walk_snmp_proto_tree(edt->tree, &ctx, 0);
                        gboolean any_snmp = ctx.has_version || ctx.has_pdu_type ||
                                            ctx.has_community || ctx.has_username ||
                                            ctx.has_error_status;
                        if (any_snmp) {
                            process_snmp_frame(&ctx);
                            snmp_packets++;
                        } else {
                            memset(&ctx, 0, sizeof(ctx));
                            ctx.info = info;
                        }
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
        if (err_info_str) g_free(err_info_str);
        if (framenum % 200 == 0) circle_vis_pump_events();
    }

    epan_dissect_free(edt);
    info->matched_packets = snmp_packets;
    info->found = (snmp_packets > 0);
    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO,
           "SNMP analysis done: %u pkts, v1=%u v2c=%u v3=%u, gets=%u sets=%u traps=%u",
           snmp_packets, info->v1_count, info->v2c_count, info->v3_count,
           info->get_count, info->set_count, info->trap_count);
    return info;
}

/* ================================================================== */
/*  Syslog Information Extraction                                     */
/* ================================================================== */

static const gchar *syslog_severity_label(guint32 sev)
{
    switch (sev) {
        case 0: return "Emergency";
        case 1: return "Alert";
        case 2: return "Critical";
        case 3: return "Error";
        case 4: return "Warning";
        case 5: return "Notice";
        case 6: return "Informational";
        case 7: return "Debug";
        default: return "Unknown";
    }
}

static const gchar *syslog_facility_label(guint32 fac)
{
    switch (fac) {
        case  0: return "kern";
        case  1: return "user";
        case  2: return "mail";
        case  3: return "daemon";
        case  4: return "auth";
        case  5: return "syslog";
        case  6: return "lpr";
        case  7: return "news";
        case  8: return "uucp";
        case  9: return "cron";
        case 10: return "authpriv";
        case 11: return "ftp";
        case 16: return "local0";
        case 17: return "local1";
        case 18: return "local2";
        case 19: return "local3";
        case 20: return "local4";
        case 21: return "local5";
        case 22: return "local6";
        case 23: return "local7";
        default: return NULL;
    }
}

static void syslog_hash_inc(GHashTable *ht, const gchar *key)
{
    if (!ht || !key || !*key) return;
    gpointer val = g_hash_table_lookup(ht, key);
    if (val) { (*(guint *)val)++; }
    else {
        guint *cnt = g_new(guint, 1); *cnt = 1;
        g_hash_table_insert(ht, g_strdup(key), cnt);
    }
}

typedef struct {
    syslog_info_t *info;
    guint32  facility;
    gboolean has_facility;
    guint32  severity;
    gboolean has_severity;
    gchar    hostname[256];
    gboolean has_hostname;
    gchar    app_name[128];
    gboolean has_app_name;
    gchar    msg_text[512];
    gboolean has_msg;
    gboolean is_rfc5424;
} syslog_walk_ctx_t;

static void walk_syslog_proto_tree(proto_node *node, syslog_walk_ctx_t *ctx, int depth)
{
    if (!node || depth > 25) return;

    field_info *fi = node->finfo;
    if (fi && fi->hfinfo && fi->hfinfo->abbrev) {
        const gchar *abbrev = fi->hfinfo->abbrev;
        gchar label[ITEM_LABEL_LENGTH];
        label[0] = '\0';

        /* Facility code (integer 0-23) */
        if (g_strcmp0(abbrev, "syslog.facility") == 0) {
            ctx->facility     = fvalue_get_uinteger(PC_FI_VALUE(fi));
            ctx->has_facility = TRUE;

        /* Severity / level — two common field names across WS versions */
        } else if (g_strcmp0(abbrev, "syslog.level")    == 0 ||
                   g_strcmp0(abbrev, "syslog.severity") == 0) {
            ctx->severity     = fvalue_get_uinteger(PC_FI_VALUE(fi));
            ctx->has_severity = TRUE;

        /* RFC 5424 version field (integer 1) */
        } else if (g_strcmp0(abbrev, "syslog.version") == 0) {
            ctx->is_rfc5424 = TRUE;

        /* Source hostname — present in both RFC 3164 and RFC 5424 */
        } else if (g_strcmp0(abbrev, "syslog.hostname") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val && g_strcmp0(val, "-") != 0) {
                g_strlcpy(ctx->hostname, val, sizeof(ctx->hostname));
                ctx->has_hostname = TRUE;
            }
            g_free(val);

        /* App/process name — RFC 5424 app-name or RFC 3164 tag */
        } else if (g_strcmp0(abbrev, "syslog.app_name") == 0 ||
                   g_strcmp0(abbrev, "syslog.appname")  == 0 ||
                   g_strcmp0(abbrev, "syslog.tag")       == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val && g_strcmp0(val, "-") != 0) {
                g_strlcpy(ctx->app_name, val, sizeof(ctx->app_name));
                ctx->has_app_name = TRUE;
            }
            g_free(val);

        /* Message payload — two common field name spellings */
        } else if (g_strcmp0(abbrev, "syslog.msg")        == 0 ||
                   g_strcmp0(abbrev, "syslog.msgpayload") == 0) {
            if (!ctx->has_msg) {
                fill_label_compat(fi, label);
                gchar *val = label_value(label);
                if (val && *val) {
                    g_strlcpy(ctx->msg_text, val, sizeof(ctx->msg_text));
                    ctx->has_msg = TRUE;
                }
                g_free(val);
            }
        }
    }

    for (proto_node *child = node->first_child; child; child = child->next)
        walk_syslog_proto_tree(child, ctx, depth + 1);
}

static void process_syslog_frame(syslog_walk_ctx_t *ctx)
{
    syslog_info_t *info = ctx->info;

    if (ctx->has_facility) {
        const gchar *fname = syslog_facility_label(ctx->facility);
        gchar fbuf[32];
        if (fname) g_snprintf(fbuf, sizeof(fbuf), "%s", fname);
        else       g_snprintf(fbuf, sizeof(fbuf), "fac%u", ctx->facility);
        syslog_hash_inc(info->facility_counts, fbuf);
    }

    if (ctx->has_severity && ctx->severity < 8)
        info->severity_counts[ctx->severity]++;

    if (ctx->is_rfc5424) info->rfc5424_count++;
    else                  info->rfc3164_count++;

    if (ctx->has_hostname)  add_unique_string(&info->hostnames,  ctx->hostname);
    if (ctx->has_app_name)  add_unique_string(&info->app_names,  ctx->app_name);

    /* Collect critical message samples (severity 0-3) up to 15 entries */
    if (ctx->has_msg && ctx->has_severity && ctx->severity <= 3 &&
        g_list_length(info->critical_msgs) < 15) {
        gchar *entry = g_strdup_printf("[%s]  %s",
            syslog_severity_label(ctx->severity), ctx->msg_text);
        info->critical_msgs = g_list_append(info->critical_msgs, entry);
    }

    memset(ctx, 0, sizeof(*ctx));
    ctx->info = info;
}

void packet_analyzer_free_syslog_info(syslog_info_t *info)
{
    if (!info) return;
    if (info->facility_counts) g_hash_table_destroy(info->facility_counts);
    if (info->hostnames)       g_list_free_full(info->hostnames,     g_free);
    if (info->app_names)       g_list_free_full(info->app_names,     g_free);
    if (info->critical_msgs)   g_list_free_full(info->critical_msgs, g_free);
    g_free(info);
}

syslog_info_t* packet_analyzer_extract_syslog_info(capture_file *cf,
                                                    const gchar *addr_a,
                                                    const gchar *addr_b,
                                                    guint16 port,
                                                    gboolean addr_is_mac)
{
    syslog_info_t *info = g_new0(syslog_info_t, 1);
    info->facility_counts = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);

    if (!cf || cf->state != FILE_READ_DONE || !cf->provider.frames || cf->count == 0)
        return info;

    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO,
           "Syslog analysis: addr_a=%s addr_b=%s port=%u (%u frames)",
           addr_a ? addr_a : "?", addr_b ? addr_b : "?", port, cf->count);

    syslog_walk_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.info = info;

    epan_dissect_t *edt = epan_dissect_new(cf->epan, TRUE, TRUE);
    if (!edt) {
        ws_log(WS_LOG_DOMAIN, LOG_LEVEL_ERROR, "Syslog: epan_dissect_new() returned NULL");
        return info;
    }
    guint32 syslog_packets = 0;

    for (guint32 framenum = 1; framenum <= cf->count; framenum++) {
        frame_data *fdata = frame_data_sequence_find(cf->provider.frames, framenum);
        if (!fdata || fdata->file_off < 0) continue;

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
                        walk_syslog_proto_tree(edt->tree, &ctx, 0);
                        gboolean any_syslog = ctx.has_facility || ctx.has_severity ||
                                              ctx.has_hostname  || ctx.has_msg;
                        if (any_syslog) {
                            process_syslog_frame(&ctx);
                            syslog_packets++;
                        } else {
                            memset(&ctx, 0, sizeof(ctx));
                            ctx.info = info;
                        }
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
        if (err_info_str) g_free(err_info_str);
        if (framenum % 200 == 0) circle_vis_pump_events();
    }

    epan_dissect_free(edt);
    info->matched_packets = syslog_packets;
    info->found = (syslog_packets > 0);
    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO,
           "Syslog analysis done: %u pkts, %u rfc3164, %u rfc5424, crit=%u",
           syslog_packets, info->rfc3164_count, info->rfc5424_count,
           info->severity_counts[0] + info->severity_counts[1] +
           info->severity_counts[2] + info->severity_counts[3]);
    return info;
}

/* ================================================================== */
/*  SSH / SFTP / SCP Information Extraction                           */
/* ================================================================== */

/* SSH RFC 4250 message codes */
#define SSH_MSG_DISCONNECT          1
#define SSH_MSG_KEXINIT             20
#define SSH_MSG_NEWKEYS             21
#define SSH_MSG_USERAUTH_REQUEST    50
#define SSH_MSG_USERAUTH_FAILURE    51
#define SSH_MSG_USERAUTH_SUCCESS    52
#define SSH_MSG_CHANNEL_OPEN        90
#define SSH_MSG_CHANNEL_REQUEST     98

/* Store a comma-separated algorithm list into a GList, first occurrence only. */
static void ssh_store_alg_list(GList **list, const gchar *csv)
{
    if (!csv || !*csv || *list != NULL) return;  /* only populate once */
    gchar **toks = g_strsplit(csv, ",", 64);
    for (int i = 0; toks[i]; i++) {
        gchar *s = g_strstrip(toks[i]);
        if (*s) *list = g_list_append(*list, g_strdup(s));
    }
    g_strfreev(toks);
}

typedef struct {
    ssh_info_t *info;
    /* Per-frame collected fields */
    gchar    protocol_str[256];
    gboolean has_protocol;
    guint32  message_code;
    gboolean has_message_code;
    /* KEXINIT algorithm lists (comma-separated) */
    gchar    kex_algorithms[1024];
    gboolean has_kex_algorithms;
    gchar    host_key_algorithms[512];
    gboolean has_host_key_algorithms;
    gchar    enc_c2s[512];
    gboolean has_enc_c2s;
    gchar    enc_s2c[512];
    gboolean has_enc_s2c;
    gchar    mac_c2s[512];
    gboolean has_mac_c2s;
    gchar    mac_s2c[512];
    gboolean has_mac_s2c;
    gchar    comp_c2s[256];
    gboolean has_comp_c2s;
    gchar    comp_s2c[256];
    gboolean has_comp_s2c;
    /* Auth */
    gchar    username[256];
    gboolean has_username;
    gchar    auth_method[64];
    gboolean has_auth_method;
    /* Channel */
    gchar    channel_type[128];
    gboolean has_channel_type;
    gchar    channel_req_type[128];
    gboolean has_channel_req_type;
    gchar    subsystem_name[128];
    gboolean has_subsystem_name;
    gchar    exec_command[512];
    gboolean has_exec_command;
} ssh_walk_ctx_t;

static void walk_ssh_proto_tree(proto_node *node, ssh_walk_ctx_t *ctx, int depth)
{
    if (!node || depth > 30) return;

    field_info *fi = node->finfo;
    if (fi && fi->hfinfo && fi->hfinfo->abbrev) {
        const gchar *abbrev = fi->hfinfo->abbrev;
        gchar label[ITEM_LABEL_LENGTH];
        label[0] = '\0';

        /* Version banner (both client and server emit this field) */
        if (g_strcmp0(abbrev, "ssh.protocol") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val && !ctx->has_protocol) {
                g_strlcpy(ctx->protocol_str, val, sizeof(ctx->protocol_str));
                ctx->has_protocol = TRUE;
            }
            g_free(val);

        /* SSH message code */
        } else if (g_strcmp0(abbrev, "ssh.message_code") == 0) {
            ctx->message_code     = fvalue_get_uinteger(PC_FI_VALUE(fi));
            ctx->has_message_code = TRUE;

        /* KEXINIT: key exchange algorithms */
        } else if (g_strcmp0(abbrev, "ssh.kex.algorithms") == 0 ||
                   g_strcmp0(abbrev, "ssh.kex_algorithms")  == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) {
                g_strlcpy(ctx->kex_algorithms, val, sizeof(ctx->kex_algorithms));
                ctx->has_kex_algorithms = TRUE;
            }
            g_free(val);

        /* KEXINIT: server host key algorithms */
        } else if (g_strcmp0(abbrev, "ssh.server_host_key_algorithms") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) {
                g_strlcpy(ctx->host_key_algorithms, val, sizeof(ctx->host_key_algorithms));
                ctx->has_host_key_algorithms = TRUE;
            }
            g_free(val);

        /* KEXINIT: encryption algorithms */
        } else if (g_strcmp0(abbrev, "ssh.encryption_algorithms_client_to_server") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) {
                g_strlcpy(ctx->enc_c2s, val, sizeof(ctx->enc_c2s));
                ctx->has_enc_c2s = TRUE;
            }
            g_free(val);
        } else if (g_strcmp0(abbrev, "ssh.encryption_algorithms_server_to_client") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) {
                g_strlcpy(ctx->enc_s2c, val, sizeof(ctx->enc_s2c));
                ctx->has_enc_s2c = TRUE;
            }
            g_free(val);

        /* KEXINIT: MAC algorithms */
        } else if (g_strcmp0(abbrev, "ssh.mac_algorithms_client_to_server") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) {
                g_strlcpy(ctx->mac_c2s, val, sizeof(ctx->mac_c2s));
                ctx->has_mac_c2s = TRUE;
            }
            g_free(val);
        } else if (g_strcmp0(abbrev, "ssh.mac_algorithms_server_to_client") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) {
                g_strlcpy(ctx->mac_s2c, val, sizeof(ctx->mac_s2c));
                ctx->has_mac_s2c = TRUE;
            }
            g_free(val);

        /* KEXINIT: compression algorithms */
        } else if (g_strcmp0(abbrev, "ssh.compression_algorithms_client_to_server") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) {
                g_strlcpy(ctx->comp_c2s, val, sizeof(ctx->comp_c2s));
                ctx->has_comp_c2s = TRUE;
            }
            g_free(val);
        } else if (g_strcmp0(abbrev, "ssh.compression_algorithms_server_to_client") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) {
                g_strlcpy(ctx->comp_s2c, val, sizeof(ctx->comp_s2c));
                ctx->has_comp_s2c = TRUE;
            }
            g_free(val);

        /* USERAUTH: username */
        } else if (g_strcmp0(abbrev, "ssh.username")            == 0 ||
                   g_strcmp0(abbrev, "ssh.userauth.user_name")  == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) {
                g_strlcpy(ctx->username, val, sizeof(ctx->username));
                ctx->has_username = TRUE;
            }
            g_free(val);

        /* USERAUTH: authentication method */
        } else if (g_strcmp0(abbrev, "ssh.userauth.method")  == 0 ||
                   g_strcmp0(abbrev, "ssh.userauth_method")  == 0 ||
                   g_strcmp0(abbrev, "ssh.auth_method")      == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) {
                g_strlcpy(ctx->auth_method, val, sizeof(ctx->auth_method));
                ctx->has_auth_method = TRUE;
            }
            g_free(val);

        /* CHANNEL_OPEN: channel type */
        } else if (g_strcmp0(abbrev, "ssh.channel_type")        == 0 ||
                   g_strcmp0(abbrev, "ssh.channel.type")         == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) {
                g_strlcpy(ctx->channel_type, val, sizeof(ctx->channel_type));
                ctx->has_channel_type = TRUE;
            }
            g_free(val);

        /* CHANNEL_REQUEST: request type */
        } else if (g_strcmp0(abbrev, "ssh.channel_request_type")   == 0 ||
                   g_strcmp0(abbrev, "ssh.channel.request_type")    == 0 ||
                   g_strcmp0(abbrev, "ssh.channel_req_type")        == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) {
                g_strlcpy(ctx->channel_req_type, val, sizeof(ctx->channel_req_type));
                ctx->has_channel_req_type = TRUE;
            }
            g_free(val);

        /* CHANNEL_REQUEST subsystem: subsystem name */
        } else if (g_strcmp0(abbrev, "ssh.subsystem_name")    == 0 ||
                   g_strcmp0(abbrev, "ssh.channel.subsystem") == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) {
                g_strlcpy(ctx->subsystem_name, val, sizeof(ctx->subsystem_name));
                ctx->has_subsystem_name = TRUE;
            }
            g_free(val);

        /* CHANNEL_REQUEST exec: command string */
        } else if (g_strcmp0(abbrev, "ssh.exec_command")  == 0 ||
                   g_strcmp0(abbrev, "ssh.channel.exec")  == 0) {
            fill_label_compat(fi, label);
            gchar *val = label_value(label);
            if (val && *val) {
                g_strlcpy(ctx->exec_command, val, sizeof(ctx->exec_command));
                ctx->has_exec_command = TRUE;
            }
            g_free(val);
        }
    }

    for (proto_node *child = node->first_child; child; child = child->next)
        walk_ssh_proto_tree(child, ctx, depth + 1);
}

static void process_ssh_frame(ssh_walk_ctx_t *ctx)
{
    ssh_info_t *info = ctx->info;

    /* Version banner — collect up to 2 unique banners (client + server) */
    if (ctx->has_protocol) {
        add_unique_string(&info->banners, ctx->protocol_str);
        if (!info->protocol_v2 &&
            g_str_has_prefix(ctx->protocol_str, "SSH-2"))
            info->protocol_v2 = TRUE;
    }

    /* Algorithm lists — only take from first KEXINIT (ssh_store_alg_list is no-op if list set) */
    if (ctx->has_kex_algorithms)       ssh_store_alg_list(&info->kex_algorithms,     ctx->kex_algorithms);
    if (ctx->has_host_key_algorithms)  ssh_store_alg_list(&info->host_key_algorithms, ctx->host_key_algorithms);
    if (ctx->has_enc_c2s)              ssh_store_alg_list(&info->ciphers_c2s,         ctx->enc_c2s);
    if (ctx->has_enc_s2c)              ssh_store_alg_list(&info->ciphers_s2c,         ctx->enc_s2c);
    if (ctx->has_mac_c2s)              ssh_store_alg_list(&info->macs_c2s,            ctx->mac_c2s);
    if (ctx->has_mac_s2c)              ssh_store_alg_list(&info->macs_s2c,            ctx->mac_s2c);
    if (ctx->has_comp_c2s)             ssh_store_alg_list(&info->compress_c2s,        ctx->comp_c2s);
    if (ctx->has_comp_s2c)             ssh_store_alg_list(&info->compress_s2c,        ctx->comp_s2c);

    /* Message code counters */
    if (ctx->has_message_code) {
        switch (ctx->message_code) {
            case SSH_MSG_KEXINIT:            info->kexinit_count++;       break;
            case SSH_MSG_NEWKEYS:            info->newkeys_count++;       break;
            case SSH_MSG_DISCONNECT:         info->disconnect_count++;    break;
            case SSH_MSG_USERAUTH_FAILURE:   info->auth_failure_count++;  break;
            case SSH_MSG_USERAUTH_SUCCESS:   info->auth_success_count++;  break;
            case SSH_MSG_CHANNEL_OPEN:       info->channel_count++;       break;
            default: break;
        }
    }

    /* Auth */
    if (ctx->has_username)
        add_unique_string(&info->usernames, ctx->username);
    if (ctx->has_auth_method) {
        add_unique_string(&info->auth_methods, ctx->auth_method);
        const gchar *m = ctx->auth_method;
        if (g_str_has_prefix(m, "password"))        info->has_password_auth = TRUE;
        else if (g_str_has_prefix(m, "publickey") ||
                 g_str_has_prefix(m, "public-key") ||
                 g_str_has_prefix(m, "pubkey"))     info->has_pubkey_auth   = TRUE;
        else if (g_str_has_prefix(m, "keyboard"))   info->has_kbdint_auth   = TRUE;
        else if (g_str_has_prefix(m, "gssapi"))     info->has_gssapi_auth   = TRUE;
    }

    /* Channel type (from CHANNEL_OPEN) */
    if (ctx->has_channel_type) {
        const gchar *ct = ctx->channel_type;
        if      (g_str_has_prefix(ct, "direct-tcpip") ||
                 g_str_has_prefix(ct, "forwarded-tcpip"))  info->has_tcp_forwarding   = TRUE;
        else if (g_str_has_prefix(ct, "x11"))               info->has_x11_forwarding   = TRUE;
        else if (g_str_has_prefix(ct, "auth-agent"))        info->has_agent_forwarding = TRUE;
        else if (g_str_has_prefix(ct, "session"))           info->has_shell            = TRUE;
    }

    /* Channel request type */
    if (ctx->has_channel_req_type) {
        const gchar *rt = ctx->channel_req_type;
        if      (g_strcmp0(rt, "x11-req") == 0 ||
                 g_strcmp0(rt, "x11")     == 0)            info->has_x11_forwarding = TRUE;
        else if (g_strcmp0(rt, "shell")   == 0)            info->has_shell          = TRUE;
        else if (g_strcmp0(rt, "exec")    == 0)            info->has_exec           = TRUE;
    }

    /* Subsystem */
    if (ctx->has_subsystem_name) {
        add_unique_string(&info->subsystems, ctx->subsystem_name);
        if (g_strcmp0(ctx->subsystem_name, "sftp") == 0)
            info->has_sftp = TRUE;
    }

    /* Exec command */
    if (ctx->has_exec_command) {
        info->has_exec = TRUE;
        const gchar *cmd = ctx->exec_command;
        /* SCP: exec command starts with "scp" */
        if (g_str_has_prefix(cmd, "scp ") || g_strcmp0(cmd, "scp") == 0)
            info->has_scp = TRUE;
        if (g_list_length(info->exec_commands) < 10)
            add_unique_string(&info->exec_commands, cmd);
    }

    memset(ctx, 0, sizeof(*ctx));
    ctx->info = info;
}

void packet_analyzer_free_ssh_info(ssh_info_t *info)
{
    if (!info) return;
    if (info->banners)             g_list_free_full(info->banners,             g_free);
    if (info->kex_algorithms)      g_list_free_full(info->kex_algorithms,      g_free);
    if (info->host_key_algorithms) g_list_free_full(info->host_key_algorithms, g_free);
    if (info->ciphers_c2s)         g_list_free_full(info->ciphers_c2s,         g_free);
    if (info->ciphers_s2c)         g_list_free_full(info->ciphers_s2c,         g_free);
    if (info->macs_c2s)            g_list_free_full(info->macs_c2s,            g_free);
    if (info->macs_s2c)            g_list_free_full(info->macs_s2c,            g_free);
    if (info->compress_c2s)        g_list_free_full(info->compress_c2s,        g_free);
    if (info->compress_s2c)        g_list_free_full(info->compress_s2c,        g_free);
    if (info->usernames)           g_list_free_full(info->usernames,           g_free);
    if (info->auth_methods)        g_list_free_full(info->auth_methods,        g_free);
    if (info->subsystems)          g_list_free_full(info->subsystems,          g_free);
    if (info->exec_commands)       g_list_free_full(info->exec_commands,       g_free);
    g_free(info);
}

ssh_info_t* packet_analyzer_extract_ssh_info(capture_file *cf,
                                              const gchar *addr_a,
                                              const gchar *addr_b,
                                              guint16 port,
                                              gboolean addr_is_mac)
{
    ssh_info_t *info = g_new0(ssh_info_t, 1);

    if (!cf || cf->state != FILE_READ_DONE || !cf->provider.frames || cf->count == 0)
        return info;

    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO,
           "SSH analysis: addr_a=%s addr_b=%s port=%u (%u frames)",
           addr_a ? addr_a : "?", addr_b ? addr_b : "?", port, cf->count);

    ssh_walk_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.info = info;

    epan_dissect_t *edt = epan_dissect_new(cf->epan, TRUE, TRUE);
    if (!edt) {
        ws_log(WS_LOG_DOMAIN, LOG_LEVEL_ERROR, "SSH: epan_dissect_new() returned NULL");
        return info;
    }
    guint32 ssh_packets = 0;

    for (guint32 framenum = 1; framenum <= cf->count; framenum++) {
        frame_data *fdata = frame_data_sequence_find(cf->provider.frames, framenum);
        if (!fdata || fdata->file_off < 0) continue;

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
                        walk_ssh_proto_tree(edt->tree, &ctx, 0);
                        gboolean any_ssh = ctx.has_protocol         || ctx.has_message_code     ||
                                           ctx.has_kex_algorithms   || ctx.has_enc_c2s          ||
                                           ctx.has_username         || ctx.has_channel_type     ||
                                           ctx.has_channel_req_type || ctx.has_exec_command     ||
                                           ctx.has_subsystem_name;
                        if (any_ssh) {
                            process_ssh_frame(&ctx);
                            ssh_packets++;
                        } else {
                            memset(&ctx, 0, sizeof(ctx));
                            ctx.info = info;
                        }
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
        if (err_info_str) g_free(err_info_str);
        if (framenum % 200 == 0) circle_vis_pump_events();
    }

    epan_dissect_free(edt);
    info->matched_packets = ssh_packets;
    info->found = (ssh_packets > 0);

    /* Detect compression from negotiated algorithm lists */
    if (!info->compression_enabled) {
        for (GList *n = info->compress_c2s; n; n = n->next)
            if (g_strcmp0((gchar *)n->data, "none") != 0) { info->compression_enabled = TRUE; break; }
    }
    if (!info->compression_enabled) {
        for (GList *n = info->compress_s2c; n; n = n->next)
            if (g_strcmp0((gchar *)n->data, "none") != 0) { info->compression_enabled = TRUE; break; }
    }

    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO,
           "SSH analysis done: %u pkts, banners=%u, kexinit=%u, newkeys=%u, "
           "shell=%d sftp=%d scp=%d x11=%d tcpfwd=%d agentfwd=%d",
           ssh_packets, g_list_length(info->banners),
           info->kexinit_count, info->newkeys_count,
           info->has_shell, info->has_sftp, info->has_scp,
           info->has_x11_forwarding, info->has_tcp_forwarding, info->has_agent_forwarding);
    return info;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * FTP  (port 21 control / passive data ports)
 * Fields: ftp.request.command, ftp.request.arg,
 *         ftp.response.code,   ftp.response.arg
 * ═══════════════════════════════════════════════════════════════════════════ */

static void ftp_hash_inc(GHashTable *ht, const gchar *key)
{
    if (!key || !*key) return;
    gpointer v = g_hash_table_lookup(ht, key);
    guint cnt  = v ? GPOINTER_TO_UINT(v) : 0;
    g_hash_table_insert(ht, g_strdup(key), GUINT_TO_POINTER(cnt + 1));
}

/* Parse "h1,h2,h3,h4,p1,p2" from PORT / PASV → "a.b.c.d:N" */
static gchar *ftp_parse_port_string(const gchar *s)
{
    if (!s) return NULL;
    const gchar *p = s;
    while (*p && !g_ascii_isdigit(*p)) p++;
    guint h1=0,h2=0,h3=0,h4=0,p1=0,p2=0;
    if (sscanf(p, "%u,%u,%u,%u,%u,%u", &h1,&h2,&h3,&h4,&p1,&p2) == 6)
        return g_strdup_printf("%u.%u.%u.%u:%u", h1,h2,h3,h4, p1*256+p2);
    guint eport = 0;
    if (sscanf(p, "|||%u|", &eport) == 1)
        return g_strdup_printf("(epsv):%u", eport);
    return NULL;
}

typedef struct {
    ftp_info_t  *info;
    gchar       *last_cmd;
} ftp_walk_ctx_t;

static void walk_ftp_proto_tree(proto_node *node, gpointer data)
{
    ftp_walk_ctx_t *ctx  = (ftp_walk_ctx_t *)data;
    ftp_info_t     *info = ctx->info;

    for (proto_node *child = node->first_child; child; child = child->next)
        walk_ftp_proto_tree(child, data);

    field_info *fi = PNODE_FINFO(node);
    if (!fi || !fi->hfinfo) return;
    const gchar *abbrev = fi->hfinfo->abbrev;

    gchar lbl[ITEM_LABEL_LENGTH] = {0};
    fill_label_compat(fi, lbl);
    const gchar *val = label_value(lbl);

    if (g_strcmp0(abbrev, "ftp.request.command") == 0 && val && *val) {
        gchar *cmd = g_ascii_strup(val, -1);
        ftp_hash_inc(info->cmd_counts, cmd);
        g_free(ctx->last_cmd);
        ctx->last_cmd = cmd;
        return;
    }
    if (g_strcmp0(abbrev, "ftp.request.arg") == 0 && val) {
        const gchar *cmd = ctx->last_cmd ? ctx->last_cmd : "?";
        if (g_strcmp0(cmd,"USER")==0 && !info->username)
            info->username = g_strdup(val);
        else if (g_strcmp0(cmd,"PASS")==0 && !info->password)
            info->password = g_strdup(val);
        else if (g_strcmp0(cmd,"PORT")==0 || g_strcmp0(cmd,"EPRT")==0) {
            gchar *addr = ftp_parse_port_string(val);
            if (!addr) addr = g_strdup(val);
            info->port_addrs = g_list_append(info->port_addrs, addr);
            info->active_mode = TRUE;
        }
        else if (g_strcmp0(cmd,"RETR")==0) { info->retr_count++; add_unique_string(&info->filenames, val); }
        else if (g_strcmp0(cmd,"STOR")==0 || g_strcmp0(cmd,"STOU")==0)
            { info->stor_count++; add_unique_string(&info->filenames, val); }
        else if (g_strcmp0(cmd,"DELE")==0 || g_strcmp0(cmd,"RNFR")==0)
            add_unique_string(&info->filenames, val);

        if (g_list_length(info->command_log) < 200) {
            gchar *entry = (*val) ? g_strdup_printf("%s %s", cmd, val)
                                  : g_strdup(cmd);
            info->command_log = g_list_append(info->command_log, entry);
        }
        return;
    }
    if (g_strcmp0(abbrev, "ftp.response.code") == 0 && val && *val) {
        ftp_hash_inc(info->resp_counts, val);
        int code = atoi(val);
        if (code >= 200 && code < 300) info->success_count++;
        else if (code >= 400)           info->error_count++;
        if (code == 230) info->login_success = TRUE;
        if (code == 530) info->login_failed  = TRUE;
        return;
    }
    if (g_strcmp0(abbrev, "ftp.response.arg") == 0 && val && *val) {
        /* Passive address from PASV/EPSV */
        if (g_strstr_len(val,-1,"(") || g_strstr_len(val,-1,"passive") ||
            g_strstr_len(val,-1,"Passive")) {
            gchar *addr = ftp_parse_port_string(val);
            if (addr) { info->pasv_addrs = g_list_append(info->pasv_addrs, addr);
                        info->passive_mode = TRUE; }
        }
        /* Server banner */
        if (!info->server_banner && (g_strstr_len(val,-1,"FTP") ||
                                     g_strstr_len(val,-1,"ftp")))
            info->server_banner = g_strdup(val);
        /* SYST */
        if (!info->system_type && (g_strstr_len(val,-1,"UNIX") ||
                                   g_strstr_len(val,-1,"Windows") ||
                                   g_strstr_len(val,-1,"Type:")))
            info->system_type = g_strdup(val);
        /* FEAT lines — short non-numeric values */
        gsize vlen = strlen(val);
        if (vlen > 2 && vlen < 48 && !g_ascii_isdigit(val[0]))
            add_unique_string(&info->features, val);
    }
}

void packet_analyzer_free_ftp_info(ftp_info_t *info)
{
    if (!info) return;
    g_free(info->username);     g_free(info->password);
    g_free(info->server_banner); g_free(info->system_type);
    if (info->cmd_counts)  g_hash_table_destroy(info->cmd_counts);
    if (info->resp_counts) g_hash_table_destroy(info->resp_counts);
    g_list_free_full(info->command_log, g_free);
    g_list_free_full(info->pasv_addrs,  g_free);
    g_list_free_full(info->port_addrs,  g_free);
    g_list_free_full(info->filenames,   g_free);
    g_list_free_full(info->features,    g_free);
    g_free(info);
}

ftp_info_t* packet_analyzer_extract_ftp_info(capture_file *cf,
                                              const gchar *addr_a,
                                              const gchar *addr_b,
                                              guint16 port,
                                              gboolean addr_is_mac)
{
    if (!cf || cf->state != FILE_READ_DONE || !cf->provider.frames || cf->count == 0)
        return NULL;
    if (!addr_a || !addr_b) return NULL;

    ftp_info_t *info = g_new0(ftp_info_t, 1);
    info->cmd_counts  = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
    info->resp_counts = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);

    epan_dissect_t *edt = epan_dissect_new(cf->epan, TRUE, TRUE);
    ftp_walk_ctx_t  ctx = { .info = info, .last_cmd = NULL };
    guint32 matched = 0;

    for (guint32 framenum = 1; framenum <= cf->count; framenum++) {
        frame_data *fdata = frame_data_sequence_find(cf->provider.frames, framenum);
        if (!fdata || fdata->file_off < 0) continue;

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
            read_ok = wtap_seek_read(cf->provider.wth, fdata->file_off,
                                     &rec, &buf, &err, &err_info_str);
            if (read_ok) {
                int fts = wtap_file_type_subtype(cf->provider.wth);
                tvbuff_t *tvb = tvb_new_real_data(
                    ws_buffer_start_ptr(&buf),
                    rec.rec_header.packet_header.caplen,
                    rec.rec_header.packet_header.len);
                epan_dissect_run(edt, fts, &rec, tvb, fdata, NULL);
#endif
                /* Address + port match via edt->pi */
                {
                    gchar pkt_src[MAX_ADDR_STR_LEN], pkt_dst[MAX_ADDR_STR_LEN];
                    if (addr_is_mac) {
                        address_to_str_buf(&edt->pi.dl_src,  pkt_src, sizeof(pkt_src));
                        address_to_str_buf(&edt->pi.dl_dst,  pkt_dst, sizeof(pkt_dst));
                    } else {
                        address_to_str_buf(&edt->pi.net_src, pkt_src, sizeof(pkt_src));
                        address_to_str_buf(&edt->pi.net_dst, pkt_dst, sizeof(pkt_dst));
                    }
                    gboolean addr_ok =
                        (g_strcmp0(pkt_src, addr_a)==0 && g_strcmp0(pkt_dst, addr_b)==0) ||
                        (g_strcmp0(pkt_src, addr_b)==0 && g_strcmp0(pkt_dst, addr_a)==0);
                    guint32 sp = edt->pi.srcport, dp = edt->pi.destport;
                    gboolean port_ok =
                        sp == 21 || dp == 21 || sp == 20 || dp == 20 ||
                        sp == 990|| dp == 990|| sp == port || dp == port;

                    if (addr_ok && port_ok) {
                        matched++;
                        ctx.last_cmd = NULL;
                        proto_tree_children_foreach(edt->tree, walk_ftp_proto_tree, &ctx);
                        g_free(ctx.last_cmd); ctx.last_cmd = NULL;
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
        if (err_info_str) g_free(err_info_str);
        if (matched % 200 == 0 && matched > 0) circle_vis_pump_events();
    }

    epan_dissect_free(edt);
    info->matched_packets = matched;
    info->found = (matched > 0);
    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO,
           "FTP analysis done: %u pkts, cmds=%u, retr=%u, stor=%u, features=%u",
           matched, g_hash_table_size(info->cmd_counts),
           info->retr_count, info->stor_count, g_list_length(info->features));
    return info;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Telnet  (port 23, also 992 for Telnet/TLS)
 * Fields: telnet.cmd, telnet.option, telnet.data
 * ═══════════════════════════════════════════════════════════════════════════ */

static const gchar *telnet_option_name(guint opt)
{
    switch (opt) {
        case  0: return "Binary Transmission";
        case  1: return "Echo";
        case  2: return "Reconnection";
        case  3: return "Suppress Go Ahead";
        case  5: return "Status";
        case  6: return "Timing Mark";
        case 24: return "Terminal Type";
        case 31: return "Window Size (NAWS)";
        case 32: return "Terminal Speed";
        case 33: return "Remote Flow Control";
        case 34: return "Linemode";
        case 35: return "X Display Location";
        case 36: return "Old Environment";
        case 37: return "Authentication";
        case 38: return "Encryption";
        case 39: return "New Environment";
        case 85: return "Charset";
        default: { static gchar buf[32]; snprintf(buf,sizeof(buf),"Option-%u",opt); return buf; }
    }
}

static void telnet_hash_inc(GHashTable *ht, const gchar *key)
{
    if (!key || !*key) return;
    gpointer v = g_hash_table_lookup(ht, key);
    guint cnt  = v ? GPOINTER_TO_UINT(v) : 0;
    g_hash_table_insert(ht, g_strdup(key), GUINT_TO_POINTER(cnt + 1));
}

static void telnet_scan_creds(telnet_info_t *info, const gchar *data, gsize len)
{
    if (!data || len == 0) return;
    gchar *copy = g_strndup(data, len);
    gchar **lines = g_strsplit_set(copy, "\r\n", -1);
    g_free(copy);
    gboolean next_user = FALSE, next_pass = FALSE;
    for (gint i = 0; lines[i]; i++) {
        const gchar *ln = g_strstrip(lines[i]);
        if (!*ln) continue;
        if (next_user && !info->username)  { info->username = g_strdup(ln); next_user = FALSE; }
        if (next_pass && !info->password)  { info->password = g_strdup(ln); next_pass = FALSE; }
        if (g_ascii_strcasecmp(ln,"login:")==0 || g_ascii_strcasecmp(ln,"username:")==0 ||
            g_str_has_suffix(ln," login:") || g_str_has_suffix(ln," Login:"))
            next_user = TRUE;
        if (g_ascii_strcasecmp(ln,"password:")==0 ||
            g_str_has_suffix(ln," Password:") || g_str_has_suffix(ln," password:"))
            next_pass = TRUE;
    }
    g_strfreev(lines);
}

typedef struct {
    telnet_info_t *info;
    guint          cur_cmd;
} telnet_walk_ctx_t;

static void walk_telnet_proto_tree(proto_node *node, gpointer data)
{
    telnet_walk_ctx_t *ctx  = (telnet_walk_ctx_t *)data;
    telnet_info_t     *info = ctx->info;

    for (proto_node *child = node->first_child; child; child = child->next)
        walk_telnet_proto_tree(child, data);

    field_info *fi = PNODE_FINFO(node);
    if (!fi || !fi->hfinfo) return;
    const gchar *abbrev = fi->hfinfo->abbrev;

    gchar lbl[ITEM_LABEL_LENGTH] = {0};
    fill_label_compat(fi, lbl);
    const gchar *val = label_value(lbl);

    if (g_strcmp0(abbrev,"telnet.cmd")==0 && val) {
        guint cv = 0;
        if (sscanf(val, "%u", &cv) == 1) { ctx->cur_cmd = cv; return; }
        if (g_strstr_len(val,-1,"WILL"))               ctx->cur_cmd = 251;
        else if (g_strstr_len(val,-1,"WONT"))          ctx->cur_cmd = 252;
        else if (g_strstr_len(val,-1,"DONT"))          ctx->cur_cmd = 254;
        else if (g_strstr_len(val,-1," DO ") ||
                 g_str_has_suffix(val,"DO"))           ctx->cur_cmd = 253;
        return;
    }
    if ((g_strcmp0(abbrev,"telnet.option")==0 ||
         g_strcmp0(abbrev,"telnet.opt")==0) && val) {
        guint opt = 0;
        const gchar *oname;
        if (sscanf(val, "%u", &opt) == 1) oname = telnet_option_name(opt);
        else                               oname = val;
        if (opt == 1  || g_strstr_len(oname,-1,"Echo"))     info->has_echo    = TRUE;
        if (opt == 34 || g_strstr_len(oname,-1,"Linemode")) info->has_linemode = TRUE;
        if (opt == 31 || g_strstr_len(oname,-1,"Window"))   info->has_naws     = TRUE;
        if (opt == 24 || g_strstr_len(oname,-1,"Terminal")) info->has_ttype    = TRUE;
        if (opt == 37 || g_strstr_len(oname,-1,"Auth"))     info->has_auth     = TRUE;
        if (opt == 38 || g_strstr_len(oname,-1,"Encrypt"))  info->has_encrypt  = TRUE;
        switch (ctx->cur_cmd) {
            case 251: telnet_hash_inc(info->will_opts, oname); break;
            case 252: telnet_hash_inc(info->wont_opts, oname); break;
            case 253: telnet_hash_inc(info->do_opts,   oname); break;
            case 254: telnet_hash_inc(info->dont_opts, oname); break;
            default: break;
        }
        ctx->cur_cmd = 0;
        return;
    }
    if ((g_strcmp0(abbrev,"telnet.data")==0 ||
         g_strcmp0(abbrev,"data.data")==0   ||
         g_strcmp0(abbrev,"data.text_lines")==0) && val) {
        gsize dlen = strlen(val);
        info->total_data_bytes += (guint32)dlen;
        if (info->data_s2c->len < 1024) {
            gsize take = MIN(dlen, 1024 - info->data_s2c->len);
            g_string_append_len(info->data_s2c, val, (gssize)take);
            g_string_append_c(info->data_s2c, '\n');
        }
        telnet_scan_creds(info, info->data_s2c->str, info->data_s2c->len);
    }
}

void packet_analyzer_free_telnet_info(telnet_info_t *info)
{
    if (!info) return;
    g_free(info->username); g_free(info->password);
    if (info->will_opts)  g_hash_table_destroy(info->will_opts);
    if (info->wont_opts)  g_hash_table_destroy(info->wont_opts);
    if (info->do_opts)    g_hash_table_destroy(info->do_opts);
    if (info->dont_opts)  g_hash_table_destroy(info->dont_opts);
    if (info->data_c2s)   g_string_free(info->data_c2s, TRUE);
    if (info->data_s2c)   g_string_free(info->data_s2c, TRUE);
    g_free(info);
}

telnet_info_t* packet_analyzer_extract_telnet_info(capture_file *cf,
                                                    const gchar *addr_a,
                                                    const gchar *addr_b,
                                                    guint16 port,
                                                    gboolean addr_is_mac)
{
    if (!cf || cf->state != FILE_READ_DONE || !cf->provider.frames || cf->count == 0)
        return NULL;
    if (!addr_a || !addr_b) return NULL;

    telnet_info_t *info = g_new0(telnet_info_t, 1);
    info->will_opts = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
    info->wont_opts = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
    info->do_opts   = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
    info->dont_opts = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
    info->data_c2s  = g_string_new(NULL);
    info->data_s2c  = g_string_new(NULL);

    epan_dissect_t    *edt = epan_dissect_new(cf->epan, TRUE, TRUE);
    telnet_walk_ctx_t  ctx = { .info = info, .cur_cmd = 0 };
    guint32 matched = 0;

    for (guint32 framenum = 1; framenum <= cf->count; framenum++) {
        frame_data *fdata = frame_data_sequence_find(cf->provider.frames, framenum);
        if (!fdata || fdata->file_off < 0) continue;

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
            read_ok = wtap_seek_read(cf->provider.wth, fdata->file_off,
                                     &rec, &buf, &err, &err_info_str);
            if (read_ok) {
                int fts = wtap_file_type_subtype(cf->provider.wth);
                tvbuff_t *tvb = tvb_new_real_data(
                    ws_buffer_start_ptr(&buf),
                    rec.rec_header.packet_header.caplen,
                    rec.rec_header.packet_header.len);
                epan_dissect_run(edt, fts, &rec, tvb, fdata, NULL);
#endif
                {
                    gchar pkt_src[MAX_ADDR_STR_LEN], pkt_dst[MAX_ADDR_STR_LEN];
                    if (addr_is_mac) {
                        address_to_str_buf(&edt->pi.dl_src,  pkt_src, sizeof(pkt_src));
                        address_to_str_buf(&edt->pi.dl_dst,  pkt_dst, sizeof(pkt_dst));
                    } else {
                        address_to_str_buf(&edt->pi.net_src, pkt_src, sizeof(pkt_src));
                        address_to_str_buf(&edt->pi.net_dst, pkt_dst, sizeof(pkt_dst));
                    }
                    gboolean addr_ok =
                        (g_strcmp0(pkt_src, addr_a)==0 && g_strcmp0(pkt_dst, addr_b)==0) ||
                        (g_strcmp0(pkt_src, addr_b)==0 && g_strcmp0(pkt_dst, addr_a)==0);
                    guint32 sp = edt->pi.srcport, dp = edt->pi.destport;
                    gboolean port_ok =
                        sp == 23 || dp == 23 || sp == 992 || dp == 992 ||
                        sp == port || dp == port;

                    if (addr_ok && port_ok) {
                        matched++;
                        ctx.cur_cmd = 0;
                        proto_tree_children_foreach(edt->tree, walk_telnet_proto_tree, &ctx);
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
        if (err_info_str) g_free(err_info_str);
        if (matched % 200 == 0 && matched > 0) circle_vis_pump_events();
    }

    epan_dissect_free(edt);
    info->matched_packets = matched;
    info->found = (matched > 0);
    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO,
           "Telnet analysis done: %u pkts, data_bytes=%u, opts=%u",
           matched, info->total_data_bytes,
           g_hash_table_size(info->will_opts) + g_hash_table_size(info->do_opts));
    return info;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * NBNS  (NetBIOS Name Service, UDP port 137)
 * Fields: nbns.name, nbns.addr, nbns.flags.response, nbns.flags.opcode
 * ═══════════════════════════════════════════════════════════════════════════ */

static const gchar *nbns_opcode_label(guint op)
{
    switch (op) {
        case  0: return "Query";
        case  5: return "Registration";
        case  6: return "Release";
        case  7: return "WACK";
        case  8: return "Refresh";
        default: { static gchar b[32]; snprintf(b, sizeof(b), "Op-%u", op); return b; }
    }
}

typedef struct {
    nbns_info_t *info;
    gchar        cur_name[256];
    gboolean     is_response;
    guint        opcode;
    gboolean     flag_counted;
} nbns_walk_ctx_t;

static void walk_nbns_proto_tree(proto_node *node, gpointer data)
{
    nbns_walk_ctx_t *ctx  = (nbns_walk_ctx_t *)data;
    nbns_info_t     *info = ctx->info;

    for (proto_node *child = node->first_child; child; child = child->next)
        walk_nbns_proto_tree(child, data);

    field_info *fi = PNODE_FINFO(node);
    if (!fi || !fi->hfinfo) return;
    const gchar *abbrev = fi->hfinfo->abbrev;

    gchar lbl[ITEM_LABEL_LENGTH] = {0};
    fill_label_compat(fi, lbl);
    const gchar *val = label_value(lbl);

    /* Response / query flag */
    if (g_strcmp0(abbrev, "nbns.flags.response") == 0 && !ctx->flag_counted) {
        ctx->flag_counted = TRUE;
        /* val may be "0"/"1", "False"/"True", or contain "Response"/"Query" */
        guint resp_v = 0;
        if (val) sscanf(val, "%u", &resp_v);
        ctx->is_response = (resp_v != 0) ||
                           (val && g_strstr_len(val, -1, "esponse") != NULL);
        if (ctx->is_response) info->response_count++;
        else                  info->query_count++;
        return;
    }
    /* Opcode */
    if (g_strcmp0(abbrev, "nbns.flags.opcode") == 0) {
        ctx->opcode = 0;
        if (val) sscanf(val, "%u", &ctx->opcode);
        /* also check text label for opcode name */
        if (val && ctx->opcode == 0) {
            if      (g_strstr_len(val,-1,"egistration")) ctx->opcode = 5;
            else if (g_strstr_len(val,-1,"elease"))      ctx->opcode = 6;
            else if (g_strstr_len(val,-1,"WACK"))        ctx->opcode = 7;
            else if (g_strstr_len(val,-1,"efresh"))      ctx->opcode = 8;
        }
        switch (ctx->opcode) {
            case 5: info->registration_count++; break;
            case 6: info->release_count++;       break;
            case 7: info->wack_count++;          break;
            case 8: info->refresh_count++;       break;
            default: break;
        }
        return;
    }
    /* NetBIOS name in query or answer */
    if (g_strcmp0(abbrev, "nbns.name") == 0 && val && *val) {
        g_strlcpy(ctx->cur_name, val, sizeof(ctx->cur_name));
        return;
    }
    /* IP address in answer — record name→addr pair */
    if ((g_strcmp0(abbrev, "nbns.addr") == 0 ||
         g_strcmp0(abbrev, "nbns.nb_addr") == 0) && val && *val && *ctx->cur_name) {
        g_hash_table_replace(info->name_to_addr,
                             g_strdup(ctx->cur_name), g_strdup(val));
        gchar *pair_key = g_strdup_printf("%s|%s", ctx->cur_name, val);
        if (!g_hash_table_contains(info->seen_pairs, pair_key)) {
            g_hash_table_add(info->seen_pairs, pair_key);  /* takes ownership */
            nbns_entry_t *e = g_new0(nbns_entry_t, 1);
            e->name        = g_strdup(ctx->cur_name);
            e->addr        = g_strdup(val);
            e->opcode      = g_strdup(nbns_opcode_label(ctx->opcode));
            e->is_response = ctx->is_response;
            info->entries  = g_list_append(info->entries, e);
        } else {
            g_free(pair_key);
        }
    }
}

void packet_analyzer_free_nbns_info(nbns_info_t *info)
{
    if (!info) return;
    for (GList *l = info->entries; l; l = l->next) {
        nbns_entry_t *e = (nbns_entry_t *)l->data;
        g_free(e->name); g_free(e->addr); g_free(e->opcode); g_free(e);
    }
    g_list_free(info->entries);
    if (info->name_to_addr) g_hash_table_destroy(info->name_to_addr);
    if (info->seen_pairs)   g_hash_table_destroy(info->seen_pairs);
    g_free(info);
}

nbns_info_t *packet_analyzer_extract_nbns_info(capture_file *cf,
                                                const gchar *addr_a,
                                                const gchar *addr_b,
                                                gboolean addr_is_mac)
{
    if (!cf || cf->state != FILE_READ_DONE || !cf->provider.frames || cf->count == 0)
        return NULL;
    if (!addr_a || !addr_b) return NULL;

    nbns_info_t *info = g_new0(nbns_info_t, 1);
    info->name_to_addr = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
    info->seen_pairs   = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);

    epan_dissect_t  *edt = epan_dissect_new(cf->epan, TRUE, TRUE);
    nbns_walk_ctx_t  ctx = { .info = info };
    guint32 matched = 0;

    for (guint32 framenum = 1; framenum <= cf->count; framenum++) {
        frame_data *fdata = frame_data_sequence_find(cf->provider.frames, framenum);
        if (!fdata || fdata->file_off < 0) continue;

        int err = 0; gchar *err_info_str = NULL;
        wtap_rec rec; gboolean read_ok;

#if VERSION_MINOR >= 6
        wtap_rec_init(&rec, fdata->cap_len);
        read_ok = wtap_seek_read(cf->provider.wth, fdata->file_off, &rec, &err, &err_info_str);
        if (read_ok) {
            int fts = wtap_file_type_subtype(cf->provider.wth);
            epan_dissect_run(edt, fts, &rec, fdata, NULL);
#else
        {
            Buffer buf; ws_buffer_init(&buf, fdata->cap_len);
            wtap_rec_init(&rec);
            read_ok = wtap_seek_read(cf->provider.wth, fdata->file_off,
                                     &rec, &buf, &err, &err_info_str);
            if (read_ok) {
                int fts = wtap_file_type_subtype(cf->provider.wth);
                tvbuff_t *tvb = tvb_new_real_data(
                    ws_buffer_start_ptr(&buf),
                    rec.rec_header.packet_header.caplen,
                    rec.rec_header.packet_header.len);
                epan_dissect_run(edt, fts, &rec, tvb, fdata, NULL);
#endif
                {
                    gchar pkt_src[MAX_ADDR_STR_LEN], pkt_dst[MAX_ADDR_STR_LEN];
                    if (addr_is_mac) {
                        address_to_str_buf(&edt->pi.dl_src,  pkt_src, sizeof(pkt_src));
                        address_to_str_buf(&edt->pi.dl_dst,  pkt_dst, sizeof(pkt_dst));
                    } else {
                        address_to_str_buf(&edt->pi.net_src, pkt_src, sizeof(pkt_src));
                        address_to_str_buf(&edt->pi.net_dst, pkt_dst, sizeof(pkt_dst));
                    }
                    gboolean addr_ok =
                        (g_strcmp0(pkt_src, addr_a)==0 && g_strcmp0(pkt_dst, addr_b)==0) ||
                        (g_strcmp0(pkt_src, addr_b)==0 && g_strcmp0(pkt_dst, addr_a)==0);
                    guint32 sp = edt->pi.srcport, dp = edt->pi.destport;
                    gboolean port_ok = sp == 137 || dp == 137;

                    if (addr_ok && port_ok) {
                        matched++;
                        ctx.cur_name[0]  = '\0';
                        ctx.is_response  = FALSE;
                        ctx.opcode       = 0;
                        ctx.flag_counted = FALSE;
                        proto_tree_children_foreach(edt->tree, walk_nbns_proto_tree, &ctx);
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
        if (err_info_str) g_free(err_info_str);
        if (matched % 200 == 0 && matched > 0) circle_vis_pump_events();
    }

    epan_dissect_free(edt);
    info->matched_packets = matched;
    info->found = (matched > 0);
    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO,
           "NBNS analysis done: %u pkts, names=%u, regs=%u",
           matched, g_hash_table_size(info->name_to_addr), info->registration_count);
    return info;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * NetBIOS Datagram Service (port 138 UDP)
 * Fields: nbdgm.type, nbdgm.src.name, nbdgm.dst.name
 * ═══════════════════════════════════════════════════════════════════════════ */

static void nbdgm_hash_inc(GHashTable *ht, const gchar *key)
{
    if (!key || !*key) return;
    gpointer v   = g_hash_table_lookup(ht, key);
    guint    cnt = v ? GPOINTER_TO_UINT(v) : 0;
    g_hash_table_insert(ht, g_strdup(key), GUINT_TO_POINTER(cnt + 1));
}

static const gchar *nbdgm_type_label(guint t)
{
    switch (t) {
        case 0x10: return "Direct Unique";
        case 0x11: return "Direct Group";
        case 0x12: return "Broadcast";
        case 0x13: return "Datagram Error";
        case 0x14: return "Query Request";
        case 0x15: return "Positive Query Response";
        case 0x16: return "Negative Query Response";
        default:   { static gchar b[24]; snprintf(b,sizeof(b),"Type-0x%02x",t); return b; }
    }
}

typedef struct {
    nbdgm_info_t *info;
    gboolean      type_counted;
} nbdgm_walk_ctx_t;

static void walk_nbdgm_proto_tree(proto_node *node, gpointer data)
{
    nbdgm_walk_ctx_t *ctx  = (nbdgm_walk_ctx_t *)data;
    nbdgm_info_t     *info = ctx->info;

    for (proto_node *child = node->first_child; child; child = child->next)
        walk_nbdgm_proto_tree(child, data);

    field_info *fi = PNODE_FINFO(node);
    if (!fi || !fi->hfinfo) return;
    const gchar *abbrev = fi->hfinfo->abbrev;

    gchar lbl[ITEM_LABEL_LENGTH] = {0};
    fill_label_compat(fi, lbl);
    const gchar *val = label_value(lbl);

    /* Datagram type */
    if ((g_strcmp0(abbrev, "nbdgm.type") == 0 ||
         g_strcmp0(abbrev, "nbdgm.msg_type") == 0) && !ctx->type_counted) {
        ctx->type_counted = TRUE;
        guint t = 0;
        if (val) sscanf(val, "%u", &t);
        const gchar *tl = nbdgm_type_label(t);
        nbdgm_hash_inc(info->dgm_types, tl);
        switch (t) {
            case 0x10: info->direct_unique++; break;
            case 0x11: info->direct_group++;  break;
            case 0x12: info->broadcast++;     break;
            case 0x13: info->error_pkts++;    break;
            default:   break;
        }
        return;
    }
    /* Source NetBIOS name */
    if ((g_strcmp0(abbrev, "nbdgm.src.name") == 0 ||
         g_strcmp0(abbrev, "nbdgm.source_name") == 0) && val && *val)
        nbdgm_hash_inc(info->src_names, val);
    /* Destination NetBIOS name */
    if ((g_strcmp0(abbrev, "nbdgm.dst.name") == 0 ||
         g_strcmp0(abbrev, "nbdgm.dest_name") == 0) && val && *val)
        nbdgm_hash_inc(info->dst_names, val);
}

void packet_analyzer_free_nbdgm_info(nbdgm_info_t *info)
{
    if (!info) return;
    if (info->src_names) g_hash_table_destroy(info->src_names);
    if (info->dst_names) g_hash_table_destroy(info->dst_names);
    if (info->dgm_types) g_hash_table_destroy(info->dgm_types);
    g_free(info);
}

nbdgm_info_t *packet_analyzer_extract_nbdgm_info(capture_file *cf,
                                                   const gchar *addr_a,
                                                   const gchar *addr_b,
                                                   gboolean addr_is_mac)
{
    if (!cf || cf->state != FILE_READ_DONE || !cf->provider.frames || cf->count == 0)
        return NULL;
    if (!addr_a || !addr_b) return NULL;

    nbdgm_info_t *info = g_new0(nbdgm_info_t, 1);
    info->src_names = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
    info->dst_names = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
    info->dgm_types = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);

    epan_dissect_t   *edt = epan_dissect_new(cf->epan, TRUE, TRUE);
    nbdgm_walk_ctx_t  ctx = { .info = info };
    guint32 matched = 0;

    for (guint32 framenum = 1; framenum <= cf->count; framenum++) {
        frame_data *fdata = frame_data_sequence_find(cf->provider.frames, framenum);
        if (!fdata || fdata->file_off < 0) continue;

        int err = 0; gchar *err_info_str = NULL;
        wtap_rec rec; gboolean read_ok;

#if VERSION_MINOR >= 6
        wtap_rec_init(&rec, fdata->cap_len);
        read_ok = wtap_seek_read(cf->provider.wth, fdata->file_off, &rec, &err, &err_info_str);
        if (read_ok) {
            int fts = wtap_file_type_subtype(cf->provider.wth);
            epan_dissect_run(edt, fts, &rec, fdata, NULL);
#else
        {
            Buffer buf; ws_buffer_init(&buf, fdata->cap_len);
            wtap_rec_init(&rec);
            read_ok = wtap_seek_read(cf->provider.wth, fdata->file_off,
                                     &rec, &buf, &err, &err_info_str);
            if (read_ok) {
                int fts = wtap_file_type_subtype(cf->provider.wth);
                tvbuff_t *tvb = tvb_new_real_data(
                    ws_buffer_start_ptr(&buf),
                    rec.rec_header.packet_header.caplen,
                    rec.rec_header.packet_header.len);
                epan_dissect_run(edt, fts, &rec, tvb, fdata, NULL);
#endif
                {
                    gchar pkt_src[MAX_ADDR_STR_LEN], pkt_dst[MAX_ADDR_STR_LEN];
                    if (addr_is_mac) {
                        address_to_str_buf(&edt->pi.dl_src,  pkt_src, sizeof(pkt_src));
                        address_to_str_buf(&edt->pi.dl_dst,  pkt_dst, sizeof(pkt_dst));
                    } else {
                        address_to_str_buf(&edt->pi.net_src, pkt_src, sizeof(pkt_src));
                        address_to_str_buf(&edt->pi.net_dst, pkt_dst, sizeof(pkt_dst));
                    }
                    gboolean addr_ok =
                        (g_strcmp0(pkt_src, addr_a)==0 && g_strcmp0(pkt_dst, addr_b)==0) ||
                        (g_strcmp0(pkt_src, addr_b)==0 && g_strcmp0(pkt_dst, addr_a)==0);
                    guint32 sp = edt->pi.srcport, dp = edt->pi.destport;
                    gboolean port_ok = sp == 138 || dp == 138;

                    if (addr_ok && port_ok) {
                        matched++;
                        ctx.type_counted = FALSE;
                        proto_tree_children_foreach(edt->tree, walk_nbdgm_proto_tree, &ctx);
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
        if (err_info_str) g_free(err_info_str);
        if (matched % 200 == 0 && matched > 0) circle_vis_pump_events();
    }

    epan_dissect_free(edt);
    info->matched_packets = matched;
    info->found = (matched > 0);
    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO,
           "NBDGM analysis done: %u pkts, src_names=%u, dst_names=%u",
           matched, g_hash_table_size(info->src_names), g_hash_table_size(info->dst_names));
    return info;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * NetBIOS Session Service (port 139 TCP)
 * Fields: nbss.type, nbss.called_name, nbss.calling_name
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    nbss_info_t *info;
    guint        sess_type;
    gchar        calling[256];
    gchar        called[256];
    gboolean     type_counted;
} nbss_walk_ctx_t;

static void walk_nbss_proto_tree(proto_node *node, gpointer data)
{
    nbss_walk_ctx_t *ctx  = (nbss_walk_ctx_t *)data;
    nbss_info_t     *info = ctx->info;

    for (proto_node *child = node->first_child; child; child = child->next)
        walk_nbss_proto_tree(child, data);

    field_info *fi = PNODE_FINFO(node);
    if (!fi || !fi->hfinfo) return;
    const gchar *abbrev = fi->hfinfo->abbrev;

    gchar lbl[ITEM_LABEL_LENGTH] = {0};
    fill_label_compat(fi, lbl);
    const gchar *val = label_value(lbl);

    /* Session packet type — parse hex label e.g. "0x81" or "129" */
    if (g_strcmp0(abbrev, "nbss.type") == 0 && !ctx->type_counted) {
        ctx->type_counted = TRUE;
        ctx->sess_type = 0xFF;
        if (val) {
            unsigned tv = 0;
            if (sscanf(val, "0x%x", &tv) == 1 || sscanf(val, "%u", &tv) == 1)
                ctx->sess_type = (guint)tv;
        }
        switch (ctx->sess_type) {
            case 0x00: info->session_messages++; break;
            case 0x81: info->session_requests++;  break;
            case 0x82: info->session_confirms++;  break;
            case 0x83: info->session_rejects++;   break;
            case 0x84: info->retargets++;         break;
            case 0x85: info->keepalives++;        break;
            default:   break;
        }
        return;
    }
    /* Called name (server side) */
    if (g_strcmp0(abbrev, "nbss.called_name") == 0 && val && *val)
        g_strlcpy(ctx->called, val, sizeof(ctx->called));
    /* Calling name (client side) */
    if (g_strcmp0(abbrev, "nbss.calling_name") == 0 && val && *val)
        g_strlcpy(ctx->calling, val, sizeof(ctx->calling));
}

void packet_analyzer_free_nbss_info(nbss_info_t *info)
{
    if (!info) return;
    for (GList *l = info->sessions; l; l = l->next) {
        nbss_session_t *s = (nbss_session_t *)l->data;
        g_free(s->calling_name); g_free(s->called_name); g_free(s);
    }
    g_list_free(info->sessions);
    g_free(info);
}

nbss_info_t *packet_analyzer_extract_nbss_info(capture_file *cf,
                                                const gchar *addr_a,
                                                const gchar *addr_b,
                                                gboolean addr_is_mac)
{
    if (!cf || cf->state != FILE_READ_DONE || !cf->provider.frames || cf->count == 0)
        return NULL;
    if (!addr_a || !addr_b) return NULL;

    nbss_info_t *info = g_new0(nbss_info_t, 1);

    epan_dissect_t  *edt = epan_dissect_new(cf->epan, TRUE, TRUE);
    nbss_walk_ctx_t  ctx = { .info = info };
    guint32 matched = 0;

    for (guint32 framenum = 1; framenum <= cf->count; framenum++) {
        frame_data *fdata = frame_data_sequence_find(cf->provider.frames, framenum);
        if (!fdata || fdata->file_off < 0) continue;

        int err = 0; gchar *err_info_str = NULL;
        wtap_rec rec; gboolean read_ok;

#if VERSION_MINOR >= 6
        wtap_rec_init(&rec, fdata->cap_len);
        read_ok = wtap_seek_read(cf->provider.wth, fdata->file_off, &rec, &err, &err_info_str);
        if (read_ok) {
            int fts = wtap_file_type_subtype(cf->provider.wth);
            epan_dissect_run(edt, fts, &rec, fdata, NULL);
#else
        {
            Buffer buf; ws_buffer_init(&buf, fdata->cap_len);
            wtap_rec_init(&rec);
            read_ok = wtap_seek_read(cf->provider.wth, fdata->file_off,
                                     &rec, &buf, &err, &err_info_str);
            if (read_ok) {
                int fts = wtap_file_type_subtype(cf->provider.wth);
                tvbuff_t *tvb = tvb_new_real_data(
                    ws_buffer_start_ptr(&buf),
                    rec.rec_header.packet_header.caplen,
                    rec.rec_header.packet_header.len);
                epan_dissect_run(edt, fts, &rec, tvb, fdata, NULL);
#endif
                {
                    gchar pkt_src[MAX_ADDR_STR_LEN], pkt_dst[MAX_ADDR_STR_LEN];
                    if (addr_is_mac) {
                        address_to_str_buf(&edt->pi.dl_src,  pkt_src, sizeof(pkt_src));
                        address_to_str_buf(&edt->pi.dl_dst,  pkt_dst, sizeof(pkt_dst));
                    } else {
                        address_to_str_buf(&edt->pi.net_src, pkt_src, sizeof(pkt_src));
                        address_to_str_buf(&edt->pi.net_dst, pkt_dst, sizeof(pkt_dst));
                    }
                    gboolean addr_ok =
                        (g_strcmp0(pkt_src, addr_a)==0 && g_strcmp0(pkt_dst, addr_b)==0) ||
                        (g_strcmp0(pkt_src, addr_b)==0 && g_strcmp0(pkt_dst, addr_a)==0);
                    guint32 sp = edt->pi.srcport, dp = edt->pi.destport;
                    gboolean port_ok = sp == 139 || dp == 139;

                    if (addr_ok && port_ok) {
                        matched++;
                        ctx.sess_type    = 0xFF;
                        ctx.calling[0]   = '\0';
                        ctx.called[0]    = '\0';
                        ctx.type_counted = FALSE;
                        proto_tree_children_foreach(edt->tree, walk_nbss_proto_tree, &ctx);
                        /* Record session setup pairs */
                        if (ctx.sess_type == 0x81 && *ctx.calling && *ctx.called) {
                            nbss_session_t *s = g_new0(nbss_session_t, 1);
                            s->calling_name = g_strdup(ctx.calling);
                            s->called_name  = g_strdup(ctx.called);
                            info->sessions  = g_list_append(info->sessions, s);
                        }
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
        if (err_info_str) g_free(err_info_str);
        if (matched % 200 == 0 && matched > 0) circle_vis_pump_events();
    }

    epan_dissect_free(edt);
    info->matched_packets = matched;
    info->found = (matched > 0);
    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO,
           "NBSS analysis done: %u pkts, requests=%u, confirms=%u, rejects=%u",
           matched, info->session_requests, info->session_confirms, info->session_rejects);
    return info;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Generic TCP Transport Statistics
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    tcp_stat_info_t *info;
    gboolean         this_pkt_is_syn;   /* reset per packet */
} tcp_stat_walk_ctx_t;

static void walk_tcp_stat_tree(proto_tree *node, gpointer data)
{
    tcp_stat_walk_ctx_t *ctx = (tcp_stat_walk_ctx_t *)data;
    tcp_stat_info_t     *info = ctx->info;
    if (!node) return;

    field_info *fi = PNODE_FINFO(node);
    if (fi && fi->hfinfo && fi->hfinfo->abbrev) {
        const gchar *abbrev = fi->hfinfo->abbrev;
        gchar lbl[512]; lbl[0] = '\0';
        fill_label_compat(fi, lbl);
        guint32 uv = 0; gdouble dv = 0.0;

        /* ── Flags ── */
        if (g_strcmp0(abbrev, "tcp.flags") == 0) {
            if (sscanf(lbl, "0x%x", &uv) == 1 || sscanf(lbl, "%u", &uv) == 1) {
                if (uv & 0x002) { info->saw_syn = TRUE; ctx->this_pkt_is_syn = TRUE; }
                if (uv & 0x010) info->saw_ack = TRUE;
                if (uv & 0x001) info->saw_fin = TRUE;
                if (uv & 0x004) info->saw_rst = TRUE;
                if (uv & 0x008) info->saw_psh = TRUE;
                if (uv & 0x020) info->saw_urg = TRUE;
                if (uv & 0x040) info->saw_ece = TRUE;
                if (uv & 0x080) info->saw_cwr = TRUE;
            }
        }
        /* ── MSS (from SYN option) ── */
        else if (g_strcmp0(abbrev, "tcp.options.mss.val") == 0) {
            if (sscanf(lbl, "%u", &uv) == 1 && uv > 0 && info->mss == 0)
                info->mss = uv;
        }
        /* ── Window size ── */
        else if (g_strcmp0(abbrev, "tcp.window_size_value") == 0) {
            if (sscanf(lbl, "%u", &uv) == 1) {
                if (info->win_count == 0 || uv < info->win_min) info->win_min = uv;
                if (uv > info->win_max)                         info->win_max = uv;
                info->win_sum += uv;
                info->win_count++;
            }
        }
        /* ── Options negotiated ── */
        else if (g_strcmp0(abbrev, "tcp.options.sack_perm") == 0) {
            info->sack_permitted = TRUE;
        }
        else if (strncmp(abbrev, "tcp.options.timestamp", 21) == 0
                 && g_strcmp0(abbrev, "tcp.options.timestamp.tsval") != 0
                 && g_strcmp0(abbrev, "tcp.options.timestamp.tsecr") != 0) {
            info->timestamps = TRUE;
        }
        else if (g_strcmp0(abbrev, "tcp.options.wscale.shift") == 0) {
            if (sscanf(lbl, "%u", &uv) == 1 && info->window_scale < 0)
                info->window_scale = (gint)uv;
        }
        /* ── RTT (Wireshark analysis field, seconds) ── */
        else if (g_strcmp0(abbrev, "tcp.analysis.ack_rtt") == 0) {
            if (sscanf(lbl, "%lf", &dv) == 1 && dv > 0.0) {
                gdouble ms = dv * 1000.0;
                if (info->rtt_count == 0 || ms < info->rtt_min_ms) info->rtt_min_ms = ms;
                if (ms > info->rtt_max_ms)                          info->rtt_max_ms = ms;
                info->rtt_sum_ms += ms;
                info->rtt_count++;
            }
        }
        /* ── Retransmissions / OOO (Wireshark analysis) ── */
        else if (g_strcmp0(abbrev, "tcp.analysis.retransmission") == 0
                 || g_strcmp0(abbrev, "tcp.analysis.fast_retransmission") == 0
                 || g_strcmp0(abbrev, "tcp.analysis.spurious_retransmission") == 0) {
            info->retrans_count++;
        }
        else if (g_strcmp0(abbrev, "tcp.analysis.out_of_order") == 0) {
            info->ooo_count++;
        }
    }

    proto_tree_children_foreach(node, walk_tcp_stat_tree, ctx);
}

tcp_stat_info_t *packet_analyzer_extract_tcp_stat_info(capture_file *cf,
                                                        const gchar  *addr_a,
                                                        const gchar  *addr_b,
                                                        guint16       port,
                                                        gboolean      addr_is_mac)
{
    if (!cf || cf->state != FILE_READ_DONE || !cf->provider.frames || cf->count == 0)
        return NULL;
    if (!addr_a || !addr_b) return NULL;

    tcp_stat_info_t *info = g_new0(tcp_stat_info_t, 1);
    info->window_scale = -1;
    info->win_min      = G_MAXUINT32;

    epan_dissect_t      *edt = epan_dissect_new(cf->epan, TRUE, TRUE);
    tcp_stat_walk_ctx_t  ctx = { .info = info, .this_pkt_is_syn = FALSE };
    guint32 matched = 0;

    for (guint32 framenum = 1; framenum <= cf->count; framenum++) {
        frame_data *fdata = frame_data_sequence_find(cf->provider.frames, framenum);
        if (!fdata || fdata->file_off < 0) continue;

        int err = 0; gchar *err_info_str = NULL;
        wtap_rec rec; gboolean read_ok;

#if VERSION_MINOR >= 6
        wtap_rec_init(&rec, fdata->cap_len);
        read_ok = wtap_seek_read(cf->provider.wth, fdata->file_off, &rec, &err, &err_info_str);
        if (read_ok) {
            int fts = wtap_file_type_subtype(cf->provider.wth);
            epan_dissect_run(edt, fts, &rec, fdata, NULL);
#else
        {
            Buffer buf; ws_buffer_init(&buf, fdata->cap_len);
            wtap_rec_init(&rec);
            read_ok = wtap_seek_read(cf->provider.wth, fdata->file_off,
                                     &rec, &buf, &err, &err_info_str);
            if (read_ok) {
                int fts = wtap_file_type_subtype(cf->provider.wth);
                tvbuff_t *tvb = tvb_new_real_data(
                    ws_buffer_start_ptr(&buf),
                    rec.rec_header.packet_header.caplen,
                    rec.rec_header.packet_header.len);
                epan_dissect_run(edt, fts, &rec, tvb, fdata, NULL);
#endif
                {
                    gchar pkt_src[MAX_ADDR_STR_LEN], pkt_dst[MAX_ADDR_STR_LEN];
                    if (addr_is_mac) {
                        address_to_str_buf(&edt->pi.dl_src,  pkt_src, sizeof(pkt_src));
                        address_to_str_buf(&edt->pi.dl_dst,  pkt_dst, sizeof(pkt_dst));
                    } else {
                        address_to_str_buf(&edt->pi.net_src, pkt_src, sizeof(pkt_src));
                        address_to_str_buf(&edt->pi.net_dst, pkt_dst, sizeof(pkt_dst));
                    }
                    gboolean addr_ok =
                        (g_strcmp0(pkt_src, addr_a)==0 && g_strcmp0(pkt_dst, addr_b)==0) ||
                        (g_strcmp0(pkt_src, addr_b)==0 && g_strcmp0(pkt_dst, addr_a)==0);

                    guint32 sp = edt->pi.srcport, dp = edt->pi.destport;
                    gboolean port_ok = (port == 0) || (sp == port || dp == port);

                    if (addr_ok && port_ok && edt->pi.ptype == PT_TCP) {
                        matched++;
                        ctx.this_pkt_is_syn = FALSE;
                        proto_tree_children_foreach(edt->tree, walk_tcp_stat_tree, &ctx);
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
        if (err_info_str) g_free(err_info_str);
        if (matched % 300 == 0 && matched > 0) circle_vis_pump_events();
    }

    epan_dissect_free(edt);

    /* Sanitise mins in case no packets matched */
    if (info->win_min == G_MAXUINT32) info->win_min = 0;

    info->matched_packets = matched;
    info->found = (matched > 0);
    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO,
           "TCP-stat analysis done: %u pkts matched, win=%u..%u, rtt_samples=%u",
           matched, info->win_min, info->win_max, info->rtt_count);
    return info;
}

void packet_analyzer_free_tcp_stat_info(tcp_stat_info_t *info)
{
    g_free(info);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Generic UDP Transport Statistics
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    udp_stat_info_t *info;
    const gchar     *addr_a;   /* for direction tracking */
    gchar            pkt_src[MAX_ADDR_STR_LEN];
    gboolean         got_payload;
} udp_stat_walk_ctx_t;

static void walk_udp_stat_tree(proto_tree *node, gpointer data)
{
    udp_stat_walk_ctx_t *ctx  = (udp_stat_walk_ctx_t *)data;
    udp_stat_info_t     *info = ctx->info;
    if (!node) return;

    field_info *fi = PNODE_FINFO(node);
    if (fi && fi->hfinfo && fi->hfinfo->abbrev && !ctx->got_payload) {
        const gchar *abbrev = fi->hfinfo->abbrev;
        /* udp.length includes 8-byte header → payload = length - 8 */
        if (g_strcmp0(abbrev, "udp.length") == 0) {
            gchar lbl[64]; lbl[0] = '\0';
            fill_label_compat(fi, lbl);
            guint32 ulen = 0;
            if (sscanf(lbl, "%u", &ulen) == 1 && ulen >= 8) {
                guint32 payload = ulen - 8;
                if (info->payload_count == 0 || payload < info->payload_min)
                    info->payload_min = payload;
                if (payload > info->payload_max)
                    info->payload_max = payload;
                info->payload_sum += payload;
                info->payload_count++;
                ctx->got_payload = TRUE;
            }
        }
    }

    proto_tree_children_foreach(node, walk_udp_stat_tree, ctx);
}

udp_stat_info_t *packet_analyzer_extract_udp_stat_info(capture_file *cf,
                                                        const gchar  *addr_a,
                                                        const gchar  *addr_b,
                                                        guint16       port,
                                                        gboolean      addr_is_mac)
{
    if (!cf || cf->state != FILE_READ_DONE || !cf->provider.frames || cf->count == 0)
        return NULL;
    if (!addr_a || !addr_b) return NULL;

    udp_stat_info_t *info = g_new0(udp_stat_info_t, 1);
    info->payload_min = G_MAXUINT32;

    epan_dissect_t      *edt = epan_dissect_new(cf->epan, TRUE, TRUE);
    guint32 matched = 0;

    for (guint32 framenum = 1; framenum <= cf->count; framenum++) {
        frame_data *fdata = frame_data_sequence_find(cf->provider.frames, framenum);
        if (!fdata || fdata->file_off < 0) continue;

        int err = 0; gchar *err_info_str = NULL;
        wtap_rec rec; gboolean read_ok;

#if VERSION_MINOR >= 6
        wtap_rec_init(&rec, fdata->cap_len);
        read_ok = wtap_seek_read(cf->provider.wth, fdata->file_off, &rec, &err, &err_info_str);
        if (read_ok) {
            int fts = wtap_file_type_subtype(cf->provider.wth);
            epan_dissect_run(edt, fts, &rec, fdata, NULL);
#else
        {
            Buffer buf; ws_buffer_init(&buf, fdata->cap_len);
            wtap_rec_init(&rec);
            read_ok = wtap_seek_read(cf->provider.wth, fdata->file_off,
                                     &rec, &buf, &err, &err_info_str);
            if (read_ok) {
                int fts = wtap_file_type_subtype(cf->provider.wth);
                tvbuff_t *tvb = tvb_new_real_data(
                    ws_buffer_start_ptr(&buf),
                    rec.rec_header.packet_header.caplen,
                    rec.rec_header.packet_header.len);
                epan_dissect_run(edt, fts, &rec, tvb, fdata, NULL);
#endif
                {
                    gchar pkt_src[MAX_ADDR_STR_LEN], pkt_dst[MAX_ADDR_STR_LEN];
                    if (addr_is_mac) {
                        address_to_str_buf(&edt->pi.dl_src,  pkt_src, sizeof(pkt_src));
                        address_to_str_buf(&edt->pi.dl_dst,  pkt_dst, sizeof(pkt_dst));
                    } else {
                        address_to_str_buf(&edt->pi.net_src, pkt_src, sizeof(pkt_src));
                        address_to_str_buf(&edt->pi.net_dst, pkt_dst, sizeof(pkt_dst));
                    }
                    gboolean addr_ok =
                        (g_strcmp0(pkt_src, addr_a)==0 && g_strcmp0(pkt_dst, addr_b)==0) ||
                        (g_strcmp0(pkt_src, addr_b)==0 && g_strcmp0(pkt_dst, addr_a)==0);

                    guint32 sp = edt->pi.srcport, dp = edt->pi.destport;
                    gboolean port_ok = (port == 0) || (sp == port || dp == port);

                    if (addr_ok && port_ok && edt->pi.ptype == PT_UDP) {
                        matched++;
                        /* direction */
                        if (g_strcmp0(pkt_src, addr_a) == 0)
                            info->pkts_a_to_b++;
                        else
                            info->pkts_b_to_a++;

                        udp_stat_walk_ctx_t wctx = { .info = info, .addr_a = addr_a, .got_payload = FALSE };
                        g_strlcpy(wctx.pkt_src, pkt_src, sizeof(wctx.pkt_src));
                        proto_tree_children_foreach(edt->tree, walk_udp_stat_tree, &wctx);
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
        if (err_info_str) g_free(err_info_str);
        if (matched % 300 == 0 && matched > 0) circle_vis_pump_events();
    }

    epan_dissect_free(edt);

    if (info->payload_min == G_MAXUINT32) info->payload_min = 0;

    info->matched_packets = matched;
    info->found = (matched > 0);
    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO,
           "UDP-stat analysis done: %u pkts matched, payload=%u..%u",
           matched, info->payload_min, info->payload_max);
    return info;
}

void packet_analyzer_free_udp_stat_info(udp_stat_info_t *info)
{
    g_free(info);
}
