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

/* Analysis mode — drives data collection strategy and UI presentation */
typedef enum {
    ANALYSIS_MODE_L3_IP,   /* Normal IP-level analysis (default) */
    ANALYSIS_MODE_L2_MAC,  /* MAC-level analysis */
    ANALYSIS_MODE_WIFI     /* Wi-Fi monitor mode: STA↔BSSID, RSSI coloring */
} AnalysisMode;

#ifdef __cplusplus
extern "C" {
#endif

/* Communication pair structure */
typedef struct _comm_pair {
    gchar *src_addr;      /* Source address (MAC or IP) - raw, for filter construction */
    gchar *dst_addr;      /* Destination address (MAC or IP) - raw, for filter construction */
    gchar *resolved_src;  /* Resolved display name (hostname or raw addr) - for UI display */
    gchar *resolved_dst;  /* Resolved display name (hostname or raw addr) - for UI display */
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
    GHashTable *dst_ports; /* Destination port -> port_stats_t* (per-port protocol + count) */

    /* --- Wi-Fi monitor mode fields (only populated when is_wifi == TRUE) --- */
    gboolean is_wifi;       /* TRUE if this pair comes from a Wi-Fi monitor capture */
    gchar   *wifi_bssid;    /* AP BSSID for this pair */
    gchar   *wifi_ssid;     /* SSID associated with the BSSID (may be NULL) */
    guint16  wifi_channel;  /* Channel number (0 = unknown) */
    gint16   rssi_min;      /* Minimum observed RSSI in dBm */
    gint16   rssi_max;      /* Maximum observed RSSI in dBm */
    gint32   rssi_sum;      /* Running sum for average calculation */
    guint32  rssi_count;    /* Number of RSSI samples */
    guint32  retry_count;   /* Number of 802.11 retry frames */
    guint8   fc_type;       /* Last observed 802.11 frame type (0=mgmt,1=ctrl,2=data) */
    guint8   fc_subtype;    /* Last observed 802.11 frame subtype */

    /* Frame type counters */
    guint32  mgmt_frame_count;   /* Management frames (type 0) */
    guint32  ctrl_frame_count;   /* Control frames (type 1) */
    guint32  data_frame_count;   /* Data frames (type 2) */

    /* Management subtype counters */
    guint32  beacon_count;       /* Beacons (subtype 0x08) */
    guint32  probe_req_count;    /* Probe Requests (subtype 0x04) */
    guint32  probe_resp_count;   /* Probe Responses (subtype 0x05) */
    guint32  auth_count;         /* Authentication (subtype 0x0B) */
    guint32  deauth_count;       /* Deauthentication (subtype 0x0C) */
    guint32  assoc_req_count;    /* Association Request (subtype 0x00) */
    guint32  assoc_resp_count;   /* Association Response (subtype 0x01) */
    guint32  reassoc_req_count;  /* Reassociation Request (subtype 0x02) */
    guint32  disassoc_count;     /* Disassociation (subtype 0x0A) */

    /* Reason codes (last seen, 0 = none) */
    guint16  deauth_reason;      /* Reason code from last deauthentication frame */
    guint16  disassoc_reason;    /* Reason code from last disassociation frame */

    /* PHY type for Wi-Fi standard identification */
    guint8   wifi_phy;  /* wlan_radio.phy: 4=b, 5=a, 6=g, 7=n, 8=ac, 9=ax, 10=be */
} comm_pair_t;

/* Per-port statistics: tracks packet count and which transport protocols use this port */
typedef struct _port_stats {
    guint64 count;     /* Number of packets on this port */
    gboolean is_tcp;   /* TRUE if TCP packets seen on this port */
    gboolean is_udp;   /* TRUE if UDP packets seen on this port */
} port_stats_t;

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
    AnalysisMode mode;     /* Analysis mode used to produce this result */
    gchar *encap_name;     /* Non-NULL for WAN/non-Ethernet encaps (e.g. "Frame Relay", "PPP").
                            * MAC mode is automatically disabled for these capture types.
                            * Caller must NOT free this — freed by packet_analyzer_free_result(). */
} analysis_result_t;

/* TLS certificate information */
typedef struct _tls_cert_info {
    gchar *subject_cn;        /* Common Name from subject */
    gchar *issuer_cn;         /* Common Name / Organization from issuer */
    gchar *not_before;        /* Validity start */
    gchar *not_after;         /* Validity end */
    gchar *serial_number;     /* Certificate serial number */
    GList *san_dns_names;     /* List of SAN DNS names (gchar*) */
} tls_cert_info_t;

/* TLS connection information extracted from handshake packets */
typedef struct _tls_info {
    gchar *version;           /* TLS version string (e.g. "TLS 1.2") */
    gchar *cipher_suite;      /* Selected cipher suite */
    gchar *sni;               /* Server Name Indication */
    gchar *alpn;              /* ALPN negotiated protocol (e.g. "h2") */
    gchar *sig_algorithm;     /* Signature algorithm (e.g. "rsa_pss_rsae_sha256") */
    gchar *ja4;               /* JA4 client fingerprint (if available) */
    gchar *ja4s;              /* JA4S server fingerprint (FoxIO plugin) */
    GList *certificates;      /* List of tls_cert_info_t* */
    guint handshake_count;    /* Number of TLS handshake packets found */
    guint32 matched_packets;  /* Total packets matching the conversation filter */
    gboolean found;           /* TRUE if any TLS data was found */
} tls_info_t;

/* SMB/CIFS connection information extracted from SMB packets */
typedef struct _smb_info {
    gboolean is_smb2;         /* TRUE if SMB2/3, FALSE if SMB1 */
    gchar *dialect;           /* Negotiated dialect (e.g. "SMB 3.1.1 (0x0311)") */
    gchar *native_os;         /* SMB1: Native OS */
    gchar *native_lanman;     /* SMB1: Native LAN Manager */

    /* Authentication */
    gchar *auth_domain;       /* NTLMSSP / SMB2 domain */
    gchar *auth_username;     /* NTLMSSP / SMB2 username */
    gchar *auth_hostname;     /* NTLMSSP / SMB2 host */
    gchar *target_name;       /* NTLMSSP challenge target name (server) */

    /* Shares and files */
    GList *tree_paths;        /* Unique share paths (gchar*) */
    GList *filenames;         /* Unique filenames (gchar*, capped at 100) */
    guint  filename_total;    /* Total filenames seen (before cap) */

    /* Named pipes and DCE/RPC */
    GList *named_pipes;       /* Unique named pipe paths from dcerpc.cn_sec_addr */
    GList *dcerpc_interfaces; /* Unique DCE/RPC interface UUIDs (gchar*) */

    /* Command statistics */
    GHashTable *cmd_counts;   /* Command label (gchar*) → count (GUINT_TO_POINTER) */

    guint32 matched_packets;  /* Total packets matching the conversation */
    gboolean found;           /* TRUE if any SMB data was found */
} smb_info_t;

/* HTTP request entry (one per request found in the capture) */
typedef struct _http_request_entry {
    gchar *method;            /* GET, POST, PUT, ... */
    gchar *uri;               /* Request URI */
    gchar *host;              /* Host header for this request */
} http_request_entry_t;

/* HTTP connection information extracted from request/response packets */
typedef struct _http_info {
    GList *hosts;             /* Unique Host header values (gchar*) */
    GList *user_agents;       /* Unique User-Agent values (gchar*) */
    GList *servers;           /* Unique Server header values (gchar*) */
    GList *content_types;     /* Unique Content-Type values (gchar*) */
    GList *requests;          /* List of http_request_entry_t* */
    GHashTable *status_codes; /* status_code string (gchar*) → count (guint) */
    guint request_count;      /* Total HTTP requests */
    guint response_count;     /* Total HTTP responses */
    guint32 matched_packets;  /* Total packets matching the conversation */
    gboolean found;           /* TRUE if any HTTP data was found */
} http_info_t;

/* Kerberos authentication information extracted from port 88 traffic */
typedef struct _kerberos_info {
    gchar *realm;              /* Primary realm (from kerberos.realm) */
    gchar *client_realm;       /* Client realm (from kerberos.crealm) */

    /* Principals */
    GList *client_names;       /* Unique CNameString values (gchar*) */
    GList *service_names;      /* Unique SNameString values (gchar*) */

    /* Encryption */
    GList *encryption_types;   /* Unique etype labels (gchar*), e.g. "aes256-cts-hmac-sha1-96 (18)" */

    /* Message statistics */
    GHashTable *msg_type_counts; /* Message type label (gchar*) → count (GUINT_TO_POINTER) */

    /* Errors */
    GHashTable *error_counts;  /* Error code label (gchar*) → count (GUINT_TO_POINTER) */
    GList *error_texts;        /* Unique e-text strings (gchar*) */

    guint32 matched_packets;   /* Total packets matching the conversation */
    gboolean found;            /* TRUE if any Kerberos data was found */
} kerberos_info_t;

/* Email protocol information (SMTP/IMAP/POP3 + IMF headers) */
typedef struct _email_info {
    /* Authentication */
    gchar *auth_username;      /* Username (SMTP AUTH / IMAP LOGIN / POP USER) */

    /* SMTP envelope */
    GList *mail_from;          /* Unique MAIL FROM parameters (gchar*) */
    GList *rcpt_to;            /* Unique RCPT TO parameters (gchar*) */
    GList *ehlo_domains;       /* Unique EHLO/HELO domains (gchar*) */

    /* IMAP folders */
    GList *folders;            /* Unique folder names (gchar*) */

    /* IMF email headers (from reassembled message data) */
    GList *subjects;           /* Unique Subject headers (gchar*) */
    GList *from_addrs;         /* Unique From: addresses (gchar*) */
    GList *to_addrs;           /* Unique To: addresses (gchar*) */
    GList *user_agents;        /* Unique User-Agent / X-Mailer (gchar*) */
    GList *content_types;      /* Unique Content-Type (gchar*) */

    /* Command statistics (all protocols) */
    GHashTable *cmd_counts;    /* Command name (gchar*) → count (GUINT_TO_POINTER) */

    /* Response statistics */
    GHashTable *response_counts; /* Response code/status (gchar*) → count (GUINT_TO_POINTER) */

    guint32 matched_packets;
    gboolean found;            /* TRUE if any email protocol data was found */
} email_info_t;

/* SQL database protocol information (MSSQL/TDS, MySQL/MariaDB, PostgreSQL) */
typedef struct _sql_info {
    gchar *db_type;            /* "MSSQL", "MySQL", "PostgreSQL" (detected from fields) */
    gchar *version;            /* Server version string */
    gchar *username;           /* Login username */
    gchar *database;           /* Database / schema name */
    gchar *server_name;        /* Server name (TDS) */
    gchar *app_name;           /* Application name (TDS) */
    gchar *client_name;        /* Client hostname (TDS) */
    gchar *auth_plugin;        /* Auth plugin (MySQL) */

    /* Queries (capped) */
    GList *queries;            /* Unique query strings (gchar*, capped at 50) */
    guint  query_total;        /* Total queries seen (before cap) */

    /* Errors */
    GList *error_messages;     /* Unique error messages (gchar*) */

    /* PostgreSQL parameters (server settings) */
    GHashTable *pg_params;     /* parameter_name → parameter_value (gchar* → gchar*) */

    /* Command / response statistics */
    GHashTable *cmd_counts;    /* Command/msg type label → count */
    GHashTable *response_counts; /* Response code/status → count */

    guint32 matched_packets;
    gboolean found;
} sql_info_t;

/* General Layer-2 frame info: EtherType values, VLAN tags, LLC DSAP/SSAP */
typedef struct _l2_info {
    GHashTable *ethertype_counts;  /* ethertype hex string (gchar*) → count (GUINT_TO_POINTER) */
    GList *ethertype_names;        /* unique "0x8100 (VLAN)" style strings (gchar*) */
    GList *vlan_ids;               /* unique VLAN IDs as strings (gchar*) */
    GList *llc_dsap_ssap;          /* unique "DSAP=0x42 SSAP=0x42 (STP)" strings (gchar*) */
    GHashTable *llc_counts;        /* "0xDS/0xSS" key (gchar*) → count (GUINT_TO_POINTER) */
    guint32 matched_packets;
    gboolean found;
} l2_info_t;

/* Spanning Tree Protocol information (STP/RSTP/MSTP/PVST+)
 * WH: expanded from minimal stub to full field set covering root bridge
 * priority/ext, all timers, per-type BPDU counters, RSTP flags, and PVST+. */
typedef struct _stp_info {
    /* ── Root bridge ────────────────────────────────────────────── */
    gchar   *root_bridge_mac;       /* stp.root.hw  — root bridge MAC */
    guint16  root_bridge_priority;  /* stp.root.pri — priority component (0–61440, steps of 4096) */
    guint16  root_bridge_ext;       /* stp.root.ext — system ID extension (= VLAN in PVST+) */
    guint32  root_path_cost;        /* stp.root.pathcost */
    gboolean is_root;               /* TRUE when this bridge is the STP root */

    /* ── Local bridge ───────────────────────────────────────────── */
    gchar   *bridge_mac;            /* stp.bridge.hw */
    guint16  bridge_priority;       /* stp.bridge.pri — priority component */
    guint16  bridge_ext;            /* stp.bridge.ext — system ID extension */
    guint16  port_id;               /* stp.port — full 16-bit port identifier */

    /* ── Timers (Wireshark label strings, e.g. "2.000" seconds) ── */
    gchar   *hello_time_str;        /* stp.hello */
    gchar   *max_age_str;           /* stp.max_age */
    gchar   *forward_delay_str;     /* stp.forward */
    gchar   *msg_age_str;           /* stp.msg_age */

    /* ── BPDU type & per-type counters ─────────────────────────── */
    gchar   *bpdu_type;             /* first BPDU type label seen */
    guint32  config_bpdu_count;     /* Configuration BPDUs (type 0x00) */
    guint32  tcn_bpdu_count;        /* Topology Change Notification BPDUs (type 0x80) */
    guint32  rst_bpdu_count;        /* RST / MST BPDUs (type 0x02) */
    guint32  topology_change_count; /* TC events: TCN BPDUs + Config BPDUs with TC flag set */

    /* ── RSTP / MSTP per-port flags ────────────────────────────── */
    gboolean flags_proposal;        /* stp.flags.proposal */
    gboolean flags_agreement;       /* stp.flags.agreement */
    gboolean flags_forwarding;      /* stp.flags.forward  */
    gboolean flags_learning;        /* stp.flags.learn    */
    gboolean flags_tca;             /* stp.flags.tca (Topology Change Acknowledgment) */

    /* ── Protocol variant & port roles ─────────────────────────── */
    gchar   *stp_variant;           /* "STP", "RSTP", "MSTP" */
    GList   *port_roles;            /* unique port role strings seen */

    /* ── PVST+ (Cisco Per-VLAN Spanning Tree Plus) ──────────────── */
    gboolean is_pvst;               /* TRUE when pvst.origvlan field detected */
    guint16  pvst_vlan;             /* originating VLAN ID */

    guint32  matched_packets;
    gboolean found;
} stp_info_t;

/* LLDP (Link Layer Discovery Protocol) information */
typedef struct _lldp_info {
    gchar *chassis_id;             /* Chassis ID value */
    gchar *port_id;                /* Port ID value */
    gchar *system_name;            /* System Name TLV */
    gchar *system_description;     /* System Description TLV */
    gchar *port_description;       /* Port Description TLV */
    GList *capabilities;           /* System capabilities strings (gchar*) */
    GList *enabled_capabilities;   /* Enabled capabilities strings (gchar*) */
    GList *management_addresses;   /* Management address strings (gchar*) */
    GList *vlan_names;             /* Org-specific VLAN name strings (gchar*) */
    guint ttl;                     /* Time To Live */
    guint32 matched_packets;
    gboolean found;
} lldp_info_t;

/* LACP (Link Aggregation Control Protocol) information */
typedef struct _lacp_info {
    gchar *actor_system;           /* Actor system MAC */
    guint16 actor_key;             /* Actor operational key */
    guint16 actor_port;            /* Actor port number */
    guint8 actor_state;            /* Actor state bitmask */
    gchar *partner_system;         /* Partner system MAC */
    guint16 partner_key;           /* Partner operational key */
    guint16 partner_port;          /* Partner port number */
    guint8 partner_state;          /* Partner state bitmask */
    guint32 matched_packets;
    gboolean found;
} lacp_info_t;

/* 802.1Q VLAN tagging information */
typedef struct _vlan_info {
    GHashTable *vlan_id_counts; /* VLAN-ID string (gchar*) → frame count (GUINT_TO_POINTER) */
    guint32 pcp_counts[8];      /* per-PCP (Priority Code Point 0-7) frame count            */
    guint32 dei_count;          /* frames with DEI (Drop Eligible Indicator) bit set         */
    guint32 qinq_count;         /* frames carrying more than one VLAN tag (QinQ / 802.1ad)  */
    guint32 matched_packets;
    gboolean found;
} vlan_info_t;

/* 802.1X / EAP (Extensible Authentication Protocol over LAN) information */
typedef struct _eap_info {
    GList *eap_types;              /* unique EAP type strings: "EAP-TLS", "PEAP", etc. (gchar*) */
    GList *identities;             /* unique EAP identity values (gchar*) */
    guint request_count;           /* EAP Request count */
    guint response_count;          /* EAP Response count */
    guint success_count;           /* EAP Success count */
    guint failure_count;           /* EAP Failure count */
    GList *eapol_types;            /* unique EAPOL type strings: "EAP Packet", "Start", etc. */
    guint32 matched_packets;
    gboolean found;
} eap_info_t;

/* MACsec (802.1AE) information */
typedef struct _macsec_info {
    GList   *sci_values;             /* unique SCI strings — "AA:BB:CC:DD:EE:FF/0001" */
    guint8   tci_flags;              /* TCI byte from the first SecTAG seen (raw byte) */
    gboolean encryption_enabled;     /* TRUE when E bit detected in any frame          */
    gboolean sci_present;            /* TRUE when SC bit detected (SCI field included)  */
    guint32  an_counts[4];           /* per-Association-Number (0-3) frame count        */
    guint32  min_pn;                 /* smallest Packet Number seen (replay protection) */
    guint32  max_pn;                 /* largest  Packet Number seen                     */
    gboolean pn_valid;               /* TRUE once at least one PN has been read         */
    guint32  packet_count_protected; /* frames where SecTAG header fields were found    */
    guint32  matched_packets;
    gboolean found;
} macsec_info_t;

/* ARP MAC/IP mapping and anomaly information */
/* ICMP / ICMPv6 type+code statistics for a communication pair */
typedef struct _icmp_info {
    GHashTable *type_counts; /* label (gchar*) → packet count (GUINT_TO_POINTER) */
    GList      *type_labels; /* labels in insertion order (gchar*, owned by type_counts) */
    guint32     matched_packets;
    gboolean    found;
    gboolean    is_v6;       /* TRUE for ICMPv6 */
} icmp_info_t;

typedef struct _arp_info {
    guint32 request_count;          /* ARP requests (opcode 1) */
    guint32 reply_count;            /* ARP replies (opcode 2) */
    guint32 gratuitous_count;       /* Replies where sender IP == target IP */
    GList  *mac_ip_mappings;        /* Unique "MAC -> IP" strings from replies (gchar*) */
    GList  *ip_conflict_warnings;   /* IPs claimed by >1 MAC: warning strings (gchar*) */
    GList  *unsolicited_warnings;   /* Replies for IPs never requested: warning strings (gchar*) */
    guint32 matched_packets;        /* Total ARP packets found in trace */
    gboolean found;
} arp_info_t;

/* DHCP session information (Discover/Offer/Request/ACK/NAK/Release/Decline/Inform) */
typedef struct _dhcp_info {
    /* Message type counters */
    guint32 discover_count;
    guint32 offer_count;
    guint32 request_count;
    guint32 ack_count;
    guint32 nak_count;
    guint32 release_count;
    guint32 decline_count;
    guint32 inform_count;
    /* Addresses */
    GList *client_macs;         /* Unique client hardware addresses (gchar*) */
    GList *requested_ips;       /* ciaddr from REQUEST messages (gchar*) */
    GList *offered_ips;         /* yiaddr from OFFER messages (gchar*) */
    GList *assigned_ips;        /* yiaddr from ACK messages (gchar*) */
    GList *server_ids;          /* DHCP server IPs / option 54 (gchar*) */
    /* Options */
    GList *hostnames;           /* option 12: client host names (gchar*) */
    GList *domain_names;        /* option 15: domain names (gchar*) */
    GList *routers;             /* option 3: default gateways (gchar*) */
    GList *dns_servers;         /* option 6: DNS server IPs (gchar*) */
    GList *lease_times;         /* option 51: formatted lease time strings (gchar*) */
    GList *requested_options;   /* option 55: parameter names the client requested (gchar*) */
    guint32 matched_packets;    /* Total DHCP packets found in trace */
    gboolean found;
} dhcp_info_t;

/* LDAP session information (LDAP / LDAPS / Global Catalog) */
typedef struct _ldap_info {
    /* Operation counters */
    guint32 bind_count;              /* BindRequest frames */
    guint32 search_count;            /* SearchRequest frames */
    guint32 search_res_entry_count;  /* Total SearchResultEntry frames */
    guint32 modify_count;            /* ModifyRequest / ModDNRequest frames */
    guint32 add_count;               /* AddRequest frames */
    guint32 delete_count;            /* DelRequest frames */
    /* Bind details */
    GList   *bind_dns;               /* Unique bind DNs from BindRequest (gchar*) */
    GList   *sasl_mechanisms;        /* Unique SASL mechanisms (gchar*) */
    gboolean has_simple_bind;        /* Simple authentication seen */
    gboolean has_sasl_bind;          /* SASL authentication seen */
    gboolean has_anonymous_bind;     /* Simple bind with empty DN */
    /* Search details */
    GList   *base_dns;               /* Unique search base DNs (gchar*) */
    GList   *search_filters;         /* Unique search filters — up to 30 (gchar*) */
    /* Results */
    GHashTable *result_counts;       /* result code name (gchar*) → guint* count */
    guint32 success_count;           /* resultCode == 0 (success) */
    guint32 error_count;             /* any non-zero resultCode */
    /* Meta */
    guint32  matched_packets;
    gboolean found;
    gboolean is_tls;                 /* TRUE when port 636 or 3269 (LDAPS / GC/TLS) */
} ldap_info_t;

/* SNMP session information (v1 / v2c / v3, ports 161/162) */
typedef struct _snmp_info {
    /* Protocol version counters */
    guint32 v1_count;
    guint32 v2c_count;
    guint32 v3_count;
    /* PDU type counters */
    guint32 get_count;           /* GetRequest + GetNextRequest + GetBulkRequest */
    guint32 set_count;           /* SetRequest */
    guint32 response_count;      /* Response / GetResponse */
    guint32 trap_count;          /* Trap-v1 + SNMPv2-Trap */
    guint32 inform_count;        /* InformRequest */
    guint32 report_count;        /* Report */
    GHashTable *pdu_counts;      /* PDU type name (gchar*) → guint* count */
    /* Community strings (v1/v2c) */
    GList   *communities;        /* unique community strings (gchar*) */
    gboolean has_default_community; /* TRUE if "public" or "private" detected */
    /* v3 security */
    GList   *v3_usernames;       /* unique v3 USM usernames (gchar*) */
    /* Variable binding OIDs */
    GHashTable *oid_counts;      /* OID/name (gchar*) → guint* count — capped at 100 */
    /* Error status */
    GHashTable *error_counts;    /* error name (gchar*) → guint* count */
    guint32 error_total;         /* frames with error_status != noError */
    /* Meta */
    guint32  matched_packets;
    gboolean found;
} snmp_info_t;

/* Syslog session information (RFC 3164 / RFC 5424, port 514/601/6514) */
typedef struct _syslog_info {
    /* Severity counters: index 0=Emergency … 7=Debug */
    guint32 severity_counts[8];
    /* Facility counters */
    GHashTable *facility_counts; /* facility label (gchar*) → guint* count */
    /* Sources */
    GList *hostnames;            /* unique sending hostnames (gchar*) */
    GList *app_names;            /* unique app-name / process tags (gchar*) */
    /* Critical message samples — severity 0-3, up to 15 entries */
    GList *critical_msgs;        /* "[SEVERITY] message text" strings (gchar*) */
    /* RFC version breakdown */
    guint32 rfc3164_count;       /* BSD syslog (no version field) */
    guint32 rfc5424_count;       /* IETF syslog (version=1) */
    /* Meta */
    guint32  matched_packets;
    gboolean found;
} syslog_info_t;

/* SSH / SFTP / SCP session information (port 22) */
typedef struct _ssh_info {
    /* Version banners — client + server (up to 2 unique strings) */
    GList *banners;                /* "SSH-2.0-OpenSSH_x.y" strings */
    gboolean protocol_v2;          /* TRUE if any banner contains "SSH-2" */
    /* Key exchange / KEXINIT algorithm lists (from first KEXINIT seen) */
    GList *kex_algorithms;         /* preferred KEX algorithm names */
    GList *host_key_algorithms;    /* server host key types */
    GList *ciphers_c2s;            /* encryption client→server */
    GList *ciphers_s2c;            /* encryption server→client */
    GList *macs_c2s;               /* MAC client→server */
    GList *macs_s2c;               /* MAC server→client */
    GList *compress_c2s;           /* compression client→server */
    GList *compress_s2c;           /* compression server→client */
    gboolean compression_enabled;  /* TRUE if non-"none" compression algorithm seen */
    guint32 kexinit_count;         /* KEXINIT frames seen (>2 means re-keying) */
    guint32 newkeys_count;         /* SSH2_MSG_NEWKEYS frames (key rotation events) */
    /* Authentication (only visible when Wireshark has decryption keys) */
    GList *usernames;              /* unique usernames seen in USERAUTH_REQUEST */
    GList *auth_methods;           /* unique method strings: "password", "publickey", etc. */
    guint32 auth_success_count;    /* USERAUTH_SUCCESS frames */
    guint32 auth_failure_count;    /* USERAUTH_FAILURE frames */
    gboolean has_password_auth;
    gboolean has_pubkey_auth;
    gboolean has_kbdint_auth;      /* keyboard-interactive */
    gboolean has_gssapi_auth;
    /* Channel usage (only visible when Wireshark has decryption keys) */
    gboolean has_shell;            /* "shell" channel request */
    gboolean has_exec;             /* "exec" channel request */
    gboolean has_sftp;             /* "sftp" subsystem */
    gboolean has_scp;              /* exec command starting with "scp" */
    gboolean has_x11_forwarding;   /* x11-req or x11 channel type */
    gboolean has_tcp_forwarding;   /* direct-tcpip / forwarded-tcpip channel */
    gboolean has_agent_forwarding; /* auth-agent@openssh.com channel */
    GList *exec_commands;          /* sampled exec commands (up to 10) */
    GList *subsystems;             /* unique subsystem names requested */
    guint32 channel_count;         /* total SSH_MSG_CHANNEL_OPEN frames */
    guint32 disconnect_count;      /* SSH_MSG_DISCONNECT frames */
    /* Meta */
    guint32  matched_packets;
    gboolean found;
} ssh_info_t;

/* DNS query / response information extracted from DNS packets in a capture */
typedef struct _dns_info {
    gboolean  found;
    guint32   matched_packets;   /* total DNS frames scanned                   */
    guint32   query_count;       /* frames with QR=0 (query)                   */
    guint32   response_count;    /* frames with QR=1 (response)                */
    guint32   noerror_count;     /* rcode=0 (NOERROR) responses                */
    guint32   nxdomain_count;    /* rcode=3 (NXDOMAIN) responses               */
    guint32   servfail_count;    /* rcode=2 (SERVFAIL) responses               */
    guint32   refused_count;     /* rcode=5 (REFUSED)  responses               */
    guint32   other_error_count; /* other non-zero rcode responses             */
    gboolean  uses_tcp;          /* DNS-over-TCP frames seen                   */
    gboolean  uses_recursion;    /* RD flag set in at least one query          */
    GHashTable *type_counts;     /* qtype name (gchar*) → guint* count         */
    GHashTable *name_counts;     /* domain name (gchar*) → guint* count        */
    GList      *answers;         /* "name TYPE value" strings (unique, gchar*) */
    GList      *nxdomain_names;  /* names that returned NXDOMAIN (gchar*)      */
} dns_info_t;

/* VoIP protocol information (SIP, RTP, H.223) */
typedef struct _voip_info {
    /* SIP signaling */
    GList *call_ids;           /* Unique SIP Call-ID values (gchar*) */
    GList *from_addrs;         /* Unique SIP From addresses (gchar*) */
    GList *to_addrs;           /* Unique SIP To addresses (gchar*) */
    GList *user_agents;        /* Unique SIP User-Agent values (gchar*) */
    GList *content_types;      /* Unique SIP Content-Type values (gchar*) */
    gchar *auth_username;      /* SIP auth username */

    /* SIP method & status statistics */
    GHashTable *method_counts; /* SIP method (INVITE, BYE, ...) → count */
    GHashTable *status_counts; /* SIP status code string → count */

    /* RTP media */
    GList *rtp_ssrcs;          /* Unique SSRC values as hex strings (gchar*) */
    GList *rtp_payload_types;  /* Unique payload type labels (gchar*) */
    GList *rtp_setup_methods;  /* Unique setup methods (gchar*) */
    guint32 rtp_packet_count;  /* Total RTP packets */

    /* H.223 multiplexing */
    guint32 h223_mux_count;    /* Number of H.223 MUX PDUs */

    guint32 matched_packets;
    gboolean found;
} voip_info_t;

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

/**
 * Extract TLS information from packets matching a specific connection.
 * Scans the capture for TLS handshake packets and extracts certificate
 * info, SNI, version, cipher suite, etc.
 *
 * @param cf          Capture file handle
 * @param addr_a      First endpoint address (IP or MAC)
 * @param addr_b      Second endpoint address (IP or MAC)
 * @param port        Destination port (e.g. 443)
 * @param addr_is_mac TRUE if addresses are MAC, FALSE if IP
 * @return TLS info structure (caller must free with packet_analyzer_free_tls_info)
 */
tls_info_t* packet_analyzer_extract_tls_info(capture_file *cf,
                                             const gchar *addr_a,
                                             const gchar *addr_b,
                                             guint16 port,
                                             gboolean addr_is_mac);

/**
 * Free TLS info structure
 */
void packet_analyzer_free_tls_info(tls_info_t *info);

/**
 * Extract HTTP information from packets matching a specific connection.
 * Scans the capture for HTTP request/response packets and extracts headers,
 * status codes, User-Agent, Server, Host, etc.
 *
 * @param cf          Capture file handle
 * @param addr_a      First endpoint address (IP or MAC)
 * @param addr_b      Second endpoint address (IP or MAC)
 * @param port        Destination port (e.g. 80)
 * @param addr_is_mac TRUE if addresses are MAC, FALSE if IP
 * @return HTTP info structure (caller must free with packet_analyzer_free_http_info)
 */
http_info_t* packet_analyzer_extract_http_info(capture_file *cf,
                                               const gchar *addr_a,
                                               const gchar *addr_b,
                                               guint16 port,
                                               gboolean addr_is_mac);

/**
 * Free HTTP info structure
 */
void packet_analyzer_free_http_info(http_info_t *info);

/**
 * Extract SMB/CIFS information from packets matching a specific connection.
 * Scans for SMB negotiation, authentication, shares, files, and DCE/RPC.
 *
 * @param cf          Capture file handle
 * @param addr_a      First endpoint address (IP or MAC)
 * @param addr_b      Second endpoint address (IP or MAC)
 * @param port        Destination port (e.g. 445)
 * @param addr_is_mac TRUE if addresses are MAC, FALSE if IP
 * @return SMB info structure (caller must free with packet_analyzer_free_smb_info)
 */
smb_info_t* packet_analyzer_extract_smb_info(capture_file *cf,
                                             const gchar *addr_a,
                                             const gchar *addr_b,
                                             guint16 port,
                                             gboolean addr_is_mac);

/**
 * Free SMB info structure
 */
void packet_analyzer_free_smb_info(smb_info_t *info);

/**
 * Extract Kerberos information from packets matching a specific connection.
 * Scans for Kerberos AS/TGS/AP exchanges, principals, encryption types, errors.
 *
 * @param cf          Capture file handle
 * @param addr_a      First endpoint address (IP or MAC)
 * @param addr_b      Second endpoint address (IP or MAC)
 * @param port        Destination port (e.g. 88)
 * @param addr_is_mac TRUE if addresses are MAC, FALSE if IP
 * @return Kerberos info structure (caller must free with packet_analyzer_free_kerberos_info)
 */
kerberos_info_t* packet_analyzer_extract_kerberos_info(capture_file *cf,
                                                      const gchar *addr_a,
                                                      const gchar *addr_b,
                                                      guint16 port,
                                                      gboolean addr_is_mac);

/**
 * Free Kerberos info structure
 */
void packet_analyzer_free_kerberos_info(kerberos_info_t *info);

/**
 * Extract email protocol information (SMTP/IMAP/POP3) from packets.
 * Also extracts IMF headers (From, To, Subject, etc.) when available.
 *
 * @param cf          Capture file handle
 * @param addr_a      First endpoint address (IP or MAC)
 * @param addr_b      Second endpoint address (IP or MAC)
 * @param port        Destination port (25/587/465 SMTP, 143/993 IMAP, 110/995 POP3)
 * @param addr_is_mac TRUE if addresses are MAC, FALSE if IP
 * @return Email info structure (caller must free with packet_analyzer_free_email_info)
 */
email_info_t* packet_analyzer_extract_email_info(capture_file *cf,
                                                const gchar *addr_a,
                                                const gchar *addr_b,
                                                guint16 port,
                                                gboolean addr_is_mac);

/**
 * Free email info structure
 */
void packet_analyzer_free_email_info(email_info_t *info);

/**
 * Extract SQL database information from packets matching a specific connection.
 * Supports MSSQL/TDS (port 1433), MySQL/MariaDB (port 3306), PostgreSQL (port 5432).
 */
sql_info_t* packet_analyzer_extract_sql_info(capture_file *cf,
                                             const gchar *addr_a,
                                             const gchar *addr_b,
                                             guint16 port,
                                             gboolean addr_is_mac);

void packet_analyzer_free_sql_info(sql_info_t *info);

/**
 * Extract VoIP information from packets matching a specific connection.
 * Supports SIP (port 5060/5061), RTP (dynamic), and H.223.
 */
voip_info_t* packet_analyzer_extract_voip_info(capture_file *cf,
                                               const gchar *addr_a,
                                               const gchar *addr_b,
                                               guint16 port,
                                               gboolean addr_is_mac);

void packet_analyzer_free_voip_info(voip_info_t *info);

/**
 * Extract general Layer-2 frame information (EtherType values, VLAN tags, LLC).
 * Scans frames matching the given MAC pair.
 *
 * @param cf          Capture file handle
 * @param addr_a      First endpoint MAC address
 * @param addr_b      Second endpoint MAC address
 * @param addr_is_mac Must be TRUE (L2 info is always MAC-based)
 * @return L2 info structure (caller must free with packet_analyzer_free_l2_info)
 */
l2_info_t* packet_analyzer_extract_l2_info(capture_file *cf,
                                            const gchar *addr_a,
                                            const gchar *addr_b,
                                            gboolean addr_is_mac);

void packet_analyzer_free_l2_info(l2_info_t *info);

/**
 * Extract Spanning Tree Protocol information (STP/RSTP/MSTP BPDUs).
 */
stp_info_t* packet_analyzer_extract_stp_info(capture_file *cf,
                                              const gchar *addr_a,
                                              const gchar *addr_b,
                                              gboolean addr_is_mac);

void packet_analyzer_free_stp_info(stp_info_t *info);

/**
 * Extract LLDP (Link Layer Discovery Protocol) information.
 */
lldp_info_t* packet_analyzer_extract_lldp_info(capture_file *cf,
                                                const gchar *addr_a,
                                                const gchar *addr_b,
                                                gboolean addr_is_mac);

void packet_analyzer_free_lldp_info(lldp_info_t *info);

/**
 * Extract LACP (Link Aggregation Control Protocol) information.
 */
lacp_info_t* packet_analyzer_extract_lacp_info(capture_file *cf,
                                                const gchar *addr_a,
                                                const gchar *addr_b,
                                                gboolean addr_is_mac);

void packet_analyzer_free_lacp_info(lacp_info_t *info);

/**
 * Extract 802.1Q VLAN tagging information (VLAN IDs, PCP, DEI, QinQ).
 */
vlan_info_t* packet_analyzer_extract_vlan_info(capture_file *cf,
                                                const gchar *addr_a,
                                                const gchar *addr_b,
                                                gboolean addr_is_mac);

void packet_analyzer_free_vlan_info(vlan_info_t *info);

/**
 * Extract 802.1X / EAP (EAP over LAN) information.
 */
eap_info_t* packet_analyzer_extract_eap_info(capture_file *cf,
                                              const gchar *addr_a,
                                              const gchar *addr_b,
                                              gboolean addr_is_mac);

void packet_analyzer_free_eap_info(eap_info_t *info);

/**
 * Extract MACsec (802.1AE) information.
 */
macsec_info_t* packet_analyzer_extract_macsec_info(capture_file *cf,
                                                    const gchar *addr_a,
                                                    const gchar *addr_b,
                                                    gboolean addr_is_mac);

void packet_analyzer_free_macsec_info(macsec_info_t *info);

/**
 * Extract ARP MAC/IP mapping and security anomaly information.
 * Scans ALL ARP packets in the capture (broadcast-based; addr params not used for filtering).
 */
arp_info_t* packet_analyzer_extract_arp_info(capture_file *cf,
                                              const gchar *addr_a,
                                              const gchar *addr_b,
                                              gboolean addr_is_mac);

void packet_analyzer_free_arp_info(arp_info_t *info);

/**
 * Extract DHCP session information (all message types, all options).
 * Scans ALL DHCP packets in the capture (broadcast-based; addr/port params not used for filtering).
 */
dhcp_info_t* packet_analyzer_extract_dhcp_info(capture_file *cf,
                                                const gchar *addr_a,
                                                const gchar *addr_b,
                                                guint16 port,
                                                gboolean addr_is_mac);

void packet_analyzer_free_dhcp_info(dhcp_info_t *info);

/**
 * Extract DNS query/response information.
 * Scans ALL DNS frames in the capture (port 53 UDP/TCP).
 */
dns_info_t* packet_analyzer_extract_dns_info(capture_file *cf,
                                              const gchar *addr_a,
                                              const gchar *addr_b,
                                              guint16 port,
                                              gboolean addr_is_mac);

void packet_analyzer_free_dns_info(dns_info_t *info);

/**
 * Extract LDAP session information (bind DNs, search bases, result codes).
 * Covers ports 389 (LDAP), 636 (LDAPS), 3268 (Global Catalog), 3269 (GC/TLS).
 */
ldap_info_t* packet_analyzer_extract_ldap_info(capture_file *cf,
                                                const gchar *addr_a,
                                                const gchar *addr_b,
                                                guint16 port,
                                                gboolean addr_is_mac);

void packet_analyzer_free_ldap_info(ldap_info_t *info);

/**
 * Extract SNMP session information (PDU types, communities, OIDs, errors).
 * Covers ports 161 (agent) and 162 (trap receiver), UDP and TCP.
 */
snmp_info_t* packet_analyzer_extract_snmp_info(capture_file *cf,
                                                const gchar *addr_a,
                                                const gchar *addr_b,
                                                guint16 port,
                                                gboolean addr_is_mac);
void packet_analyzer_free_snmp_info(snmp_info_t *info);

/**
 * Extract Syslog session information (severity, facility, sources, messages).
 * Covers ports 514 (UDP/TCP), 601 (TCP), 6514 (TLS).
 */
syslog_info_t* packet_analyzer_extract_syslog_info(capture_file *cf,
                                                    const gchar *addr_a,
                                                    const gchar *addr_b,
                                                    guint16 port,
                                                    gboolean addr_is_mac);
void packet_analyzer_free_syslog_info(syslog_info_t *info);

/**
 * Extract SSH / SFTP / SCP session information (handshake, algorithms, auth,
 * channel usage, tunneling).  Covers port 22 (TCP).
 */
ssh_info_t* packet_analyzer_extract_ssh_info(capture_file *cf,
                                              const gchar *addr_a,
                                              const gchar *addr_b,
                                              guint16 port,
                                              gboolean addr_is_mac);
void packet_analyzer_free_ssh_info(ssh_info_t *info);

/**
 * Extract ICMP / ICMPv6 type+code statistics for a communication pair.
 * @param cf          Capture file
 * @param src_addr    Source address (IP or MAC)
 * @param dst_addr    Destination address (IP or MAC)
 * @param addr_is_mac TRUE if addresses are MAC
 * @param is_v6       TRUE for ICMPv6, FALSE for ICMP
 */
icmp_info_t* packet_analyzer_extract_icmp_info(capture_file *cf,
                                                const gchar *src_addr,
                                                const gchar *dst_addr,
                                                gboolean addr_is_mac,
                                                gboolean is_v6);
void packet_analyzer_free_icmp_info(icmp_info_t *info);

/* ── FTP ──────────────────────────────────────────────────────────────────── */

typedef struct _ftp_info {
    /* Auth */
    gchar    *username;           /* USER command value                       */
    gchar    *password;           /* PASS command value                       */
    gboolean  login_success;      /* 230 seen                                 */
    gboolean  login_failed;       /* 530 seen                                 */

    /* Commands */
    GHashTable *cmd_counts;       /* gchar* cmd → guint count                 */
    GList      *command_log;      /* "CMD arg" strings, capped at 200         */

    /* Data channel */
    GList    *pasv_addrs;         /* "addr:port" from PASV/EPSV responses     */
    GList    *port_addrs;         /* "addr:port" from PORT commands           */
    gboolean  passive_mode;
    gboolean  active_mode;

    /* Transfers */
    guint32   retr_count;
    guint32   stor_count;
    GList    *filenames;          /* args of RETR/STOR/DELE/RNFR              */

    /* Server info */
    gchar    *server_banner;      /* 220 response text                        */
    GList    *features;           /* FEAT response lines                      */
    gchar    *system_type;        /* SYST response                            */

    /* Response stats */
    GHashTable *resp_counts;      /* gchar* code → guint count                */
    guint32   success_count;      /* 2xx responses                            */
    guint32   error_count;        /* 4xx + 5xx responses                      */

    guint32   matched_packets;
    gboolean  found;
} ftp_info_t;

ftp_info_t* packet_analyzer_extract_ftp_info(capture_file *cf,
                                              const gchar *addr_a,
                                              const gchar *addr_b,
                                              guint16 port,
                                              gboolean addr_is_mac);
void packet_analyzer_free_ftp_info(ftp_info_t *info);

/* ── Telnet ───────────────────────────────────────────────────────────────── */

typedef struct _telnet_info {
    /* Option negotiations (option name string → guint count) */
    GHashTable *will_opts;
    GHashTable *wont_opts;
    GHashTable *do_opts;
    GHashTable *dont_opts;

    /* Flags for commonly important options */
    gboolean  has_echo;
    gboolean  has_linemode;
    gboolean  has_naws;          /* Negotiate About Window Size               */
    gboolean  has_ttype;         /* Terminal Type                             */
    gboolean  has_auth;          /* Authentication option                     */
    gboolean  has_encrypt;       /* Telnet Encryption option                  */

    /* Credentials extracted from data stream */
    gchar    *username;          /* line following "login:" or "Username:"    */
    gchar    *password;          /* line following "Password:"                */

    /* Reassembled data (each direction, capped at 1024 bytes total)          */
    GString  *data_c2s;          /* client → server                          */
    GString  *data_s2c;          /* server → client                          */
    guint32   total_data_bytes;  /* total bytes before cap                   */

    guint32   matched_packets;
    gboolean  found;
} telnet_info_t;

telnet_info_t* packet_analyzer_extract_telnet_info(capture_file *cf,
                                                    const gchar *addr_a,
                                                    const gchar *addr_b,
                                                    guint16 port,
                                                    gboolean addr_is_mac);
void packet_analyzer_free_telnet_info(telnet_info_t *info);

/* ── NBNS / NetBIOS Name Service (port 137 UDP) ──────────────────────── */
typedef struct _nbns_entry {
    gchar   *name;
    gchar   *addr;      /* NULL for pure queries with no answer yet */
    gchar   *opcode;    /* "Query","Registration","Release","WACK","Refresh" */
    gboolean is_response;
} nbns_entry_t;

typedef struct _nbns_info {
    GList      *entries;           /* GList of nbns_entry_t* (responses w/ addr) */
    GHashTable *name_to_addr;      /* last known name → IP */
    GHashTable *seen_pairs;        /* "name|addr" dedup set */
    guint32     query_count;
    guint32     response_count;
    guint32     registration_count;
    guint32     release_count;
    guint32     refresh_count;
    guint32     wack_count;
    guint32     matched_packets;
    gboolean    found;
} nbns_info_t;

nbns_info_t *packet_analyzer_extract_nbns_info(capture_file *cf,
                                                const gchar *addr_a,
                                                const gchar *addr_b,
                                                gboolean addr_is_mac);
void packet_analyzer_free_nbns_info(nbns_info_t *info);

/* ── NetBIOS Datagram Service (port 138 UDP) ─────────────────────────── */
typedef struct _nbdgm_info {
    GHashTable *src_names;         /* source NetBIOS name → count */
    GHashTable *dst_names;         /* dest  NetBIOS name → count */
    GHashTable *dgm_types;         /* type label → count */
    guint32     direct_unique;
    guint32     direct_group;
    guint32     broadcast;
    guint32     error_pkts;
    guint32     matched_packets;
    gboolean    found;
} nbdgm_info_t;

nbdgm_info_t *packet_analyzer_extract_nbdgm_info(capture_file *cf,
                                                   const gchar *addr_a,
                                                   const gchar *addr_b,
                                                   gboolean addr_is_mac);
void packet_analyzer_free_nbdgm_info(nbdgm_info_t *info);

/* ── NetBIOS Session Service (port 139 TCP) ──────────────────────────── */
typedef struct _nbss_session {
    gchar *calling_name;  /* client */
    gchar *called_name;   /* server */
} nbss_session_t;

typedef struct _nbss_info {
    GList   *sessions;             /* GList of nbss_session_t* */
    guint32  session_requests;
    guint32  session_confirms;
    guint32  session_rejects;
    guint32  retargets;
    guint32  keepalives;
    guint32  session_messages;
    guint32  matched_packets;
    gboolean found;
} nbss_info_t;

nbss_info_t *packet_analyzer_extract_nbss_info(capture_file *cf,
                                                const gchar *addr_a,
                                                const gchar *addr_b,
                                                gboolean addr_is_mac);
void packet_analyzer_free_nbss_info(nbss_info_t *info);

/* ── Generic TCP Transport Statistics ───────────────────────────────────
 * Aggregated TCP-level stats for any pair/port: flags observed, window
 * size, MSS, negotiated options, and RTT derived from tcp.analysis.ack_rtt */
typedef struct _tcp_stat_info {
    /* Flags ever observed in this stream */
    gboolean saw_syn;
    gboolean saw_ack;
    gboolean saw_fin;
    gboolean saw_rst;
    gboolean saw_psh;
    gboolean saw_urg;
    gboolean saw_ece;
    gboolean saw_cwr;

    /* MSS from SYN options (0 = not advertised) */
    guint32  mss;

    /* Window size (raw, in bytes) */
    guint32  win_min;
    guint32  win_max;
    gdouble  win_sum;
    guint32  win_count;

    /* Negotiated options (from SYN/SYN-ACK) */
    gboolean sack_permitted;   /* SACK OK option seen */
    gboolean timestamps;       /* TCP timestamps option seen */
    gint     window_scale;     /* window scale shift (-1 = not advertised) */

    /* RTT from tcp.analysis.ack_rtt (Wireshark per-packet analysis) */
    gdouble  rtt_min_ms;       /* milliseconds */
    gdouble  rtt_max_ms;
    gdouble  rtt_sum_ms;
    guint32  rtt_count;

    /* Packet counts */
    guint32  matched_packets;
    guint32  retrans_count;    /* tcp.analysis.retransmission present */
    guint32  ooo_count;        /* tcp.analysis.out_of_order present */
    gboolean found;
} tcp_stat_info_t;

tcp_stat_info_t *packet_analyzer_extract_tcp_stat_info(capture_file *cf,
                                                        const gchar  *addr_a,
                                                        const gchar  *addr_b,
                                                        guint16       port,
                                                        gboolean      addr_is_mac);
void packet_analyzer_free_tcp_stat_info(tcp_stat_info_t *info);

/* ── Generic UDP Transport Statistics ───────────────────────────────────
 * Payload-level stats (datagram sizes, direction counts) for any pair/port */
typedef struct _udp_stat_info {
    guint32  payload_min;      /* bytes (udp.length - 8) */
    guint32  payload_max;
    gdouble  payload_sum;
    guint32  payload_count;

    guint32  pkts_a_to_b;      /* direction A→B */
    guint32  pkts_b_to_a;      /* direction B→A */

    guint32  matched_packets;
    gboolean found;
} udp_stat_info_t;

udp_stat_info_t *packet_analyzer_extract_udp_stat_info(capture_file *cf,
                                                        const gchar  *addr_a,
                                                        const gchar  *addr_b,
                                                        guint16       port,
                                                        gboolean      addr_is_mac);
void packet_analyzer_free_udp_stat_info(udp_stat_info_t *info);

#ifdef __cplusplus
}
#endif

#endif /* PACKET_ANALYZER_H */
