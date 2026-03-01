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

#ifdef __cplusplus
}
#endif

#endif /* PACKET_ANALYZER_H */
