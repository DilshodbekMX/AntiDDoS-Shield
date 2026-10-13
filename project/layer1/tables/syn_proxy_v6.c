/**
 * @file syn_proxy_v6.c
 * @brief IPv6 TCP SYN Proxy implementation
 *
 * Implements SYN cookies for IPv6 with 128-bit address hashing.
 * Uses SipHash-2-4 for cryptographic cookie generation.
 */

#include "syn_proxy_v6.h"
#include "syn_proxy.h"

#include <string.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_cycles.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>
#include <rte_tcp.h>
#include <rte_ip.h>

#define RTE_LOGTYPE_SYN_PROXY_V6 RTE_LOGTYPE_USER4

/* Connection hash table */
static struct rte_hash *g_conn_table_v6 = NULL;
static struct syn_proxy_conn_v6 *g_conn_pool_v6 = NULL;

/* Configuration */
static struct syn_proxy_config g_config_v6;
static bool g_enabled_v6 = false;
static bool g_initialized_v6 = false;

/* Secrets for cookie generation (rotated periodically) */
static uint32_t g_secret_v6[4] = {0x12345678, 0x9abcdef0, 0x13579bdf, 0x2468ace0};
static uint32_t g_secret_prev_v6[4];  /* Previous secret for cookie validation */
static uint64_t g_secret_rotation_tsc = 0;

/* Adaptive mode */
static enum syn_proxy_mode g_current_mode_v6 = SYN_PROXY_MODE_STATEFUL;
static int g_forced_mode_v6 = -1;  /* -1 = adaptive */
static uint64_t g_last_mode_switch_tsc __attribute__((unused)) = 0;
static uint32_t g_current_syn_rate_v6 = 0;

/* Statistics */
static struct syn_proxy_stats_v6 g_stats_v6;

/* MSS table for cookie encoding (4 bits = 16 values) */
static const uint16_t MSS_TABLE[16] = {
    536, 1220, 1300, 1360, 1400, 1420, 1440, 1452,
    1460, 1480, 2900, 4460, 5800, 7300, 8960, 65535
};

/* Cookie validity window (32 seconds) */
#define COOKIE_WINDOW_BITS 5
#define COOKIE_WINDOW_MASK ((1 << COOKIE_WINDOW_BITS) - 1)
#define COOKIE_MAX_AGE 2  /* Number of windows to accept */

/* SipHash-2-4 for 128-bit key hashing */
static inline uint64_t siphash_v6(const uint8_t key[16] __rte_unused,
                                   const uint32_t secret[4],
                                   const uint8_t ip1[16], const uint8_t ip2[16],
                                   uint16_t port1, uint16_t port2)
{
    /* Simplified SipHash using DPDK jhash */
    uint32_t data[10];
    rte_memcpy(&data[0], ip1, 16);     /* 4 words */
    rte_memcpy(&data[4], ip2, 16);     /* 4 words */
    data[8] = ((uint32_t)port1 << 16) | port2;
    data[9] = secret[0] ^ secret[1];

    return rte_jhash_32b(data, 10, secret[2] ^ secret[3]);
}

/* Get current time counter (32-second windows) */
static inline uint32_t get_cookie_time(void)
{
    return (uint32_t)(rte_rdtsc() / (rte_get_tsc_hz() * 32)) & COOKIE_WINDOW_MASK;
}

/* Encode MSS into 4-bit index */
static inline uint8_t encode_mss(uint16_t mss)
{
    for (int i = 0; i < 15; i++) {
        if (mss <= MSS_TABLE[i]) {
            return (uint8_t)i;
        }
    }
    return 15;
}

/* Decode MSS from 4-bit index */
static inline uint16_t decode_mss(uint8_t idx)
{
    return MSS_TABLE[idx & 0x0F];
}

/* ==================== Cookie Generation ==================== */

uint32_t syn_cookie_v6_generate(const uint8_t client_ip[16],
                                 const uint8_t server_ip[16],
                                 uint16_t client_port,
                                 uint16_t server_port,
                                 uint32_t isn,
                                 uint16_t mss)
{
    uint32_t cookie_time = get_cookie_time();
    uint8_t mss_idx = encode_mss(mss);

    /* Hash the tuple with secret */
    uint64_t hash = siphash_v6(client_ip, g_secret_v6,
                                client_ip, server_ip,
                                client_port, server_port);

    /* XOR with ISN and time */
    hash ^= isn;
    hash ^= ((uint64_t)cookie_time << 24);

    /* Build cookie: high 27 bits from hash, 4 bits MSS, 5 bits time */
    uint32_t cookie = (uint32_t)(hash & 0x07FFFFFF) << 5;  /* 27 bits from hash */
    cookie |= ((uint32_t)mss_idx) << COOKIE_WINDOW_BITS;   /* 4 bits MSS */
    cookie |= cookie_time;                                  /* 5 bits time */

    return cookie;
}

bool syn_cookie_v6_validate(const uint8_t client_ip[16],
                             const uint8_t server_ip[16],
                             uint16_t client_port,
                             uint16_t server_port,
                             uint32_t isn,
                             uint32_t cookie_ack,
                             uint16_t *mss_out)
{
    uint32_t cookie = cookie_ack - 1;  /* ACK = cookie + 1 */
    uint32_t cookie_time = cookie & COOKIE_WINDOW_MASK;
    uint8_t mss_idx = (cookie >> COOKIE_WINDOW_BITS) & 0x0F;
    uint32_t current_time = get_cookie_time();

    /* Check time window */
    uint32_t age = (current_time - cookie_time) & COOKIE_WINDOW_MASK;
    if (age > COOKIE_MAX_AGE) {
        __atomic_add_fetch(&g_stats_v6.cookies_expired, 1, __ATOMIC_RELAXED);
        return false;
    }

    /* Regenerate cookie with current secret */
    uint32_t expected = syn_cookie_v6_generate(client_ip, server_ip,
                                                client_port, server_port,
                                                isn, decode_mss(mss_idx));

    /* Compare high bits (time and MSS are already set) */
    if (((expected ^ cookie) & 0xFFFFFFE0) == 0) {
        if (mss_out) {
            *mss_out = decode_mss(mss_idx);
        }
        __atomic_add_fetch(&g_stats_v6.cookies_valid, 1, __ATOMIC_RELAXED);
        return true;
    }

    /* Try with previous secret (for rotation window) */
    uint64_t hash_prev = siphash_v6(client_ip, g_secret_prev_v6,
                                     client_ip, server_ip,
                                     client_port, server_port);
    hash_prev ^= isn;
    hash_prev ^= ((uint64_t)cookie_time << 24);

    uint32_t expected_prev = (uint32_t)(hash_prev & 0x07FFFFFF) << 5;
    expected_prev |= ((uint32_t)mss_idx) << COOKIE_WINDOW_BITS;
    expected_prev |= cookie_time;

    if (((expected_prev ^ cookie) & 0xFFFFFFE0) == 0) {
        if (mss_out) {
            *mss_out = decode_mss(mss_idx);
        }
        __atomic_add_fetch(&g_stats_v6.cookies_valid, 1, __ATOMIC_RELAXED);
        return true;
    }

    __atomic_add_fetch(&g_stats_v6.cookies_invalid, 1, __ATOMIC_RELAXED);
    return false;
}

/* ==================== Initialization ==================== */

/* Connection key structure for hash table */
struct conn_key_v6 {
    uint8_t  client_ip[16];
    uint8_t  server_ip[16];
    uint16_t client_port;
    uint16_t server_port;
} __attribute__((packed));

static inline uint32_t conn_key_v6_hash(const void *key, uint32_t key_len __rte_unused,
                                         uint32_t init_val)
{
    const uint32_t *k = (const uint32_t *)key;
    /* Hash 36 bytes = 9 uint32_t */
    return rte_jhash_32b(k, 9, init_val);
}

int syn_proxy_v6_init(const struct syn_proxy_config *config)
{
    if (g_initialized_v6) {
        RTE_LOG(WARNING, SYN_PROXY_V6, "Already initialized\n");
        return 0;
    }

    if (!config) {
        RTE_LOG(ERR, SYN_PROXY_V6, "NULL config\n");
        return -1;
    }

    g_config_v6 = *config;

    /* Create connection hash table */
    struct rte_hash_parameters params = {
        .name = "syn_proxy_v6_conn",
        .entries = config->max_connections,
        .key_len = sizeof(struct conn_key_v6),
        .hash_func = conn_key_v6_hash,
        .hash_func_init_val = 0,
        .socket_id = rte_socket_id(),
        .extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY,
    };

    g_conn_table_v6 = rte_hash_create(&params);
    if (!g_conn_table_v6) {
        RTE_LOG(ERR, SYN_PROXY_V6, "Failed to create connection hash table\n");
        return -1;
    }

    /* Allocate connection pool */
    g_conn_pool_v6 = rte_zmalloc("syn_proxy_v6_pool",
                                  sizeof(struct syn_proxy_conn_v6) * config->max_connections,
                                  RTE_CACHE_LINE_SIZE);
    if (!g_conn_pool_v6) {
        RTE_LOG(ERR, SYN_PROXY_V6, "Failed to allocate connection pool\n");
        rte_hash_free(g_conn_table_v6);
        g_conn_table_v6 = NULL;
        return -1;
    }

    /* Initialize secrets */
    g_secret_v6[0] = config->secret;
    g_secret_v6[1] = config->secret ^ 0x12345678;
    g_secret_v6[2] = config->secret ^ 0x9abcdef0;
    g_secret_v6[3] = config->secret ^ 0xfedcba98;
    rte_memcpy(g_secret_prev_v6, g_secret_v6, sizeof(g_secret_v6));
    g_secret_rotation_tsc = rte_rdtsc();

    g_enabled_v6 = config->enabled;
    g_initialized_v6 = true;
    memset(&g_stats_v6, 0, sizeof(g_stats_v6));

    RTE_LOG(INFO, SYN_PROXY_V6,
            "IPv6 SYN proxy initialized (max_conn=%u, enabled=%d)\n",
            config->max_connections, config->enabled);

    return 0;
}

void syn_proxy_v6_cleanup(void)
{
    if (g_conn_table_v6) {
        rte_hash_free(g_conn_table_v6);
        g_conn_table_v6 = NULL;
    }

    if (g_conn_pool_v6) {
        rte_free(g_conn_pool_v6);
        g_conn_pool_v6 = NULL;
    }

    g_initialized_v6 = false;
    g_enabled_v6 = false;

    RTE_LOG(INFO, SYN_PROXY_V6, "IPv6 SYN proxy cleaned up\n");
}

bool syn_proxy_v6_is_enabled(void)
{
    return g_enabled_v6;
}

/* ==================== Helper Functions ==================== */

/* TSC Hz cached for performance */
static uint64_t g_tsc_hz_v6 = 0;

/* Per-lcore packet ID counter */
static __thread uint16_t tls_pkt_id_counter_v6 = 0;

static inline uint16_t fast_packet_id_v6(void) {
    return (uint16_t)((rte_rdtsc() & 0xFF00) | (++tls_pkt_id_counter_v6 & 0xFF));
}

static inline uint32_t fast_timestamp_ms_v6(void) {
    if (unlikely(g_tsc_hz_v6 == 0)) {
        g_tsc_hz_v6 = rte_get_tsc_hz();
    }
    return (uint32_t)(rte_rdtsc() / (g_tsc_hz_v6 / 1000));
}

/* Parse TCP options from SYN packet */
static void parse_tcp_options_v6(const struct rte_tcp_hdr *tcp,
                                  struct tcp_syn_options *opts,
                                  uint16_t max_len) {
    memset(opts, 0, sizeof(*opts));
    opts->mss = 1220;  /* Default IPv6 MSS */
    opts->wscale = 255;  /* Not present */

    if (unlikely(max_len < 20)) {
        return;
    }

    uint8_t tcp_hdr_len = (tcp->data_off >> 4) * 4;
    if (tcp_hdr_len > max_len) {
        tcp_hdr_len = max_len;
    }
    if (tcp_hdr_len <= 20) {
        return;
    }

    const uint8_t *opt = (const uint8_t *)tcp + 20;
    const uint8_t *end = (const uint8_t *)tcp + tcp_hdr_len;

    while (opt < end) {
        uint8_t kind = *opt;

        if (kind == 0) break;
        if (kind == 1) { opt++; continue; }

        if (opt + 1 >= end) break;
        uint8_t len = opt[1];
        if (len < 2 || opt + len > end) break;

        switch (kind) {
            case 2:  /* MSS */
                if (len == 4 && opt + 4 <= end) {
                    opts->mss = rte_be_to_cpu_16(*(uint16_t *)(opt + 2));
                }
                break;
            case 3:  /* Window Scale */
                if (len == 3 && opt + 3 <= end) {
                    opts->wscale = opt[2];
                }
                break;
            case 4:  /* SACK Permitted */
                opts->sack_permitted = true;
                break;
            case 8:  /* Timestamp */
                if (len == 10 && opt + 10 <= end) {
                    opts->timestamp_present = true;
                    opts->tsval = rte_be_to_cpu_32(*(uint32_t *)(opt + 2));
                    opts->tsecr = rte_be_to_cpu_32(*(uint32_t *)(opt + 6));
                }
                break;
        }
        opt += len;
    }
}

/* Calculate IPv6 TCP checksum */
static inline uint16_t calc_tcp6_checksum(const uint8_t src_ip[16],
                                           const uint8_t dst_ip[16],
                                           const struct rte_tcp_hdr *tcp,
                                           uint16_t tcp_len) {
    uint32_t sum = 0;

    /* Pseudo header - IPv6 addresses */
    const uint16_t *src = (const uint16_t *)src_ip;
    const uint16_t *dst = (const uint16_t *)dst_ip;
    for (int i = 0; i < 8; i++) {
        sum += src[i];
        sum += dst[i];
    }
    /* TCP length and protocol */
    sum += rte_cpu_to_be_16(tcp_len);
    sum += rte_cpu_to_be_16(IPPROTO_TCP);

    /* TCP header + data */
    sum += rte_raw_cksum(tcp, tcp_len);

    /* Fold */
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);

    return (uint16_t)~sum;
}

/* Build TCP options for SYN-ACK */
static uint16_t build_synack_options_v6(uint8_t *opts, uint16_t mss,
                                         bool sack_permitted,
                                         const struct tcp_syn_options *client_opts) {
    uint8_t *p = opts;

    /* MSS option (required) */
    *p++ = 2;
    *p++ = 4;
    *(uint16_t *)p = rte_cpu_to_be_16(mss);
    p += 2;

    /* SACK Permitted */
    if (sack_permitted) {
        *p++ = 4;
        *p++ = 2;
    }

    /* Timestamp */
    if (client_opts && client_opts->timestamp_present) {
        *p++ = 8;
        *p++ = 10;
        *(uint32_t *)p = rte_cpu_to_be_32(fast_timestamp_ms_v6());
        p += 4;
        *(uint32_t *)p = rte_cpu_to_be_32(client_opts->tsval);
        p += 4;
    }

    /* Window Scale */
    if (client_opts && client_opts->wscale != 255) {
        *p++ = 1;
        *p++ = 3;
        *p++ = 3;
        *p++ = 7;
    }

    /* Pad to 4-byte boundary */
    while ((p - opts) % 4 != 0) {
        *p++ = 0;
    }

    return p - opts;
}

/* Create SYN-ACK packet for IPv6 */
static struct rte_mbuf *create_synack_v6(struct rte_mempool *mempool,
                                          const struct packet_features_v6 *features,
                                          const struct rte_ether_hdr *orig_eth,
                                          uint32_t cookie,
                                          const struct tcp_syn_options *client_opts) {
    struct rte_mbuf *m = rte_pktmbuf_alloc(mempool);
    if (unlikely(!m)) {
        return NULL;
    }

    /* Calculate sizes */
    uint16_t opts_len = 4;  /* MSS always */
    if (client_opts->sack_permitted) opts_len += 2;
    if (client_opts->timestamp_present) opts_len += 10;
    if (client_opts->wscale != 255) opts_len += 4;
    opts_len = (opts_len + 3) & ~3;

    uint16_t tcp_hdr_len = 20 + opts_len;
    uint16_t payload_len = tcp_hdr_len;
    uint16_t frame_len = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv6_hdr) + tcp_hdr_len;

    char *pkt = rte_pktmbuf_mtod(m, char *);
    m->data_len = frame_len;
    m->pkt_len = frame_len;

    /* Ethernet header - swap src/dst */
    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)pkt;
    rte_ether_addr_copy(&orig_eth->src_addr, &eth->dst_addr);
    rte_ether_addr_copy(&orig_eth->dst_addr, &eth->src_addr);
    eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6);

    /* IPv6 header */
    struct rte_ipv6_hdr *ip6 = (struct rte_ipv6_hdr *)(eth + 1);
    ip6->vtc_flow = rte_cpu_to_be_32(0x60000000);  /* Version 6, no traffic class, no flow label */
    ip6->payload_len = rte_cpu_to_be_16(payload_len);
    ip6->proto = IPPROTO_TCP;
    ip6->hop_limits = 64;
    rte_memcpy(ip6->src_addr.a, features->dst_ip.v6, 16);  /* Swap */
    rte_memcpy(ip6->dst_addr.a, features->src_ip.v6, 16);

    /* TCP header */
    struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)(ip6 + 1);
    tcp->src_port = rte_cpu_to_be_16(features->dst_port);  /* Swap */
    tcp->dst_port = rte_cpu_to_be_16(features->src_port);
    tcp->sent_seq = rte_cpu_to_be_32(cookie);
    tcp->recv_ack = rte_cpu_to_be_32(features->tcp_seq + 1);
    tcp->data_off = (tcp_hdr_len / 4) << 4;
    tcp->tcp_flags = TCP_FLAG_SYN | TCP_FLAG_ACK;
    tcp->rx_win = rte_cpu_to_be_16(65535);
    tcp->cksum = 0;
    tcp->tcp_urp = 0;

    /* Build TCP options */
    uint8_t *opt_ptr = (uint8_t *)tcp + 20;
    build_synack_options_v6(opt_ptr, 1220, client_opts->sack_permitted, client_opts);

    /* Compute TCP checksum */
    tcp->cksum = calc_tcp6_checksum(ip6->src_addr.a, ip6->dst_addr.a, tcp, tcp_hdr_len);

    return m;
}

/* Transform SYN to SYN-ACK in place for IPv6 */
bool transform_syn_to_synack_v6_inplace(struct rte_mbuf *m,
                                        uint32_t cookie) {
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    struct rte_ipv6_hdr *ip6 = (struct rte_ipv6_hdr *)(eth + 1);
    struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)(ip6 + 1);

    /* Swap Ethernet addresses */
    struct rte_ether_addr tmp_mac;
    rte_ether_addr_copy(&eth->src_addr, &tmp_mac);
    rte_ether_addr_copy(&eth->dst_addr, &eth->src_addr);
    rte_ether_addr_copy(&tmp_mac, &eth->dst_addr);

    /* Swap IPv6 addresses */
    uint8_t tmp_ip[16];
    rte_memcpy(tmp_ip, ip6->src_addr.a, 16);
    rte_memcpy(ip6->src_addr.a, ip6->dst_addr.a, 16);
    rte_memcpy(ip6->dst_addr.a, tmp_ip, 16);
    ip6->hop_limits = 64;

    /* Swap TCP ports */
    uint16_t tmp_port = tcp->src_port;
    tcp->src_port = tcp->dst_port;
    tcp->dst_port = tmp_port;

    /* Set SYN-ACK fields */
    uint32_t client_seq = rte_be_to_cpu_32(tcp->sent_seq);
    tcp->recv_ack = rte_cpu_to_be_32(client_seq + 1);
    tcp->sent_seq = rte_cpu_to_be_32(cookie);
    tcp->tcp_flags = TCP_FLAG_SYN | TCP_FLAG_ACK;
    tcp->rx_win = rte_cpu_to_be_16(65535);
    tcp->cksum = 0;
    tcp->tcp_urp = 0;

    /* Minimal SYN-ACK: just MSS option (24 byte TCP header) */
    uint16_t tcp_hdr_len = 24;
    tcp->data_off = (tcp_hdr_len / 4) << 4;

    uint8_t *opt_ptr = (uint8_t *)tcp + 20;
    *opt_ptr++ = 2;   /* MSS Kind */
    *opt_ptr++ = 4;   /* MSS Length */
    *(uint16_t *)opt_ptr = rte_cpu_to_be_16(1220);  /* IPv6 MSS */

    /* Update IPv6 payload length */
    ip6->payload_len = rte_cpu_to_be_16(tcp_hdr_len);

    /* Update mbuf length */
    uint16_t frame_len = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv6_hdr) + tcp_hdr_len;
    m->data_len = frame_len;
    m->pkt_len = frame_len;
    m->ol_flags = 0;

    /* Compute TCP checksum */
    tcp->cksum = calc_tcp6_checksum(ip6->src_addr.a, ip6->dst_addr.a, tcp, tcp_hdr_len);

    return true;
}

/* Find connection with key */
static inline struct syn_proxy_conn_v6 *find_connection_v6(const struct conn_key_v6 *key) {
    int32_t idx = rte_hash_lookup(g_conn_table_v6, key);
    if (idx >= 0) {
        return &g_conn_pool_v6[idx];
    }
    return NULL;
}

/* Allocate new connection */
static inline struct syn_proxy_conn_v6 *alloc_connection_v6(const struct conn_key_v6 *key) {
    int32_t idx = rte_hash_add_key(g_conn_table_v6, key);
    if (idx < 0) {
        __atomic_add_fetch(&g_stats_v6.table_full_drops, 1, __ATOMIC_RELAXED);
        return NULL;
    }

    struct syn_proxy_conn_v6 *conn = &g_conn_pool_v6[idx];
    memset(conn, 0, sizeof(*conn));

    rte_memcpy(conn->client_ip, key->client_ip, 16);
    rte_memcpy(conn->server_ip, key->server_ip, 16);
    conn->client_port = key->client_port;
    conn->server_port = key->server_port;
    conn->state = SYN_PROXY_NONE;

    uint64_t now = rte_rdtsc();
    conn->created_tsc = now;
    conn->state_change_tsc = now;
    conn->last_client_tsc = now;

    __atomic_add_fetch(&g_stats_v6.connections_created, 1, __ATOMIC_RELAXED);
    __atomic_add_fetch(&g_stats_v6.connections_active, 1, __ATOMIC_RELAXED);

    return conn;
}

/* ==================== Packet Processing ==================== */

int syn_proxy_v6_process_packet(struct rte_mbuf *m,
                                struct packet_features_v6 *features,
                                uint8_t direction,
                                struct rte_mempool *mempool,
                                struct syn_proxy_result_v6 *result,
                                uint16_t port_id __rte_unused)
{
    if (!g_enabled_v6 || !result || !features) {
        if (result) {
            result->action = SYN_PROXY_FORWARD;
        }
        return 0;
    }

    /* Initialize result */
    result->action = SYN_PROXY_FORWARD;
    result->packet_modified = false;
    result->reply_pkt = NULL;
    result->conn_state = SYN_PROXY_NONE;
    result->conn_id = 0;

    /* Only process TCP */
    if (features->protocol != IPPROTO_TCP) {
        return 0;
    }

    uint8_t tcp_flags = features->tcp_flags;

    /* Build connection key */
    struct conn_key_v6 key;
    if (direction == DIRECTION_INBOUND) {
        /* Client -> Server */
        rte_memcpy(key.client_ip, features->src_ip.v6, 16);
        rte_memcpy(key.server_ip, features->dst_ip.v6, 16);
        key.client_port = features->src_port;
        key.server_port = features->dst_port;
    } else {
        /* Server -> Client: swap */
        rte_memcpy(key.client_ip, features->dst_ip.v6, 16);
        rte_memcpy(key.server_ip, features->src_ip.v6, 16);
        key.client_port = features->dst_port;
        key.server_port = features->src_port;
    }

    /* Look up existing connection */
    struct syn_proxy_conn_v6 *conn = find_connection_v6(&key);

    /* Handle SYN from client */
    if ((tcp_flags & TCP_FLAG_SYN) && !(tcp_flags & TCP_FLAG_ACK) &&
        direction == DIRECTION_INBOUND) {

        /* Check if we should challenge */
        if (!syn_proxy_v6_should_challenge(features)) {
            result->action = SYN_PROXY_BYPASS;
            __atomic_add_fetch(&g_stats_v6.packets_bypassed, 1, __ATOMIC_RELAXED);
            return 0;
        }

        /* Parse client TCP options */
        struct tcp_syn_options client_opts;
        struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
        struct rte_ipv6_hdr *ip6 = (struct rte_ipv6_hdr *)(eth + 1);
        struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)(ip6 + 1);
        uint16_t tcp_max_len = rte_be_to_cpu_16(ip6->payload_len);
        parse_tcp_options_v6(tcp, &client_opts, tcp_max_len);

        /* Generate cookie */
        uint32_t cookie = syn_cookie_v6_generate(
            features->src_ip.v6, features->dst_ip.v6,
            features->src_port, features->dst_port,
            features->tcp_seq, client_opts.mss);

        /* Try in-place transformation for speed */
        if (transform_syn_to_synack_v6_inplace(m, cookie)) {
            result->action = SYN_PROXY_REPLY_INPLACE;
            result->packet_modified = true;
        } else if (mempool) {
            /* Fallback to allocating new packet */
            result->reply_pkt = create_synack_v6(mempool, features, eth,
                                                  cookie, &client_opts);
            if (result->reply_pkt) {
                result->action = SYN_PROXY_REPLY;
            } else {
                result->action = SYN_PROXY_DROP;
            }
        } else {
            result->action = SYN_PROXY_DROP;
        }

        __atomic_add_fetch(&g_stats_v6.cookies_sent, 1, __ATOMIC_RELAXED);
        return 0;
    }

    /* Handle ACK from client (cookie validation) */
    if ((tcp_flags & TCP_FLAG_ACK) && !(tcp_flags & TCP_FLAG_SYN) &&
        direction == DIRECTION_INBOUND && !conn) {

        uint16_t mss;
        bool valid = syn_cookie_v6_validate(
            features->src_ip.v6, features->dst_ip.v6,
            features->src_port, features->dst_port,
            features->tcp_seq - 1,  /* Client's original ISN */
            features->tcp_ack,
            &mss);

        if (!valid) {
            /* Invalid cookie - could be attack or real connection */
            result->action = SYN_PROXY_FORWARD;
            return 0;
        }

        /* Valid cookie - create connection entry (for stateful mode) */
        if (g_current_mode_v6 == SYN_PROXY_MODE_STATEFUL) {
            conn = alloc_connection_v6(&key);
            if (conn) {
                conn->state = SYN_PROXY_ESTABLISHED;
                conn->client_isn = features->tcp_seq - 1;
                conn->cookie_isn = features->tcp_ack - 1;
                conn->client_opts.mss = mss;
                result->conn_state = SYN_PROXY_ESTABLISHED;
                __atomic_add_fetch(&g_stats_v6.connections_established, 1, __ATOMIC_RELAXED);
            }
        }

        /* Forward the ACK to server */
        result->action = SYN_PROXY_FORWARD;
        return 0;
    }

    /* Handle established connection traffic */
    if (conn) {
        uint64_t now = rte_rdtsc();
        result->conn_state = conn->state;

        if (direction == DIRECTION_INBOUND) {
            conn->last_client_tsc = now;
            conn->packets_c2s++;
            conn->bytes_c2s += features->packet_size;
            __atomic_add_fetch(&g_stats_v6.packets_proxied_c2s, 1, __ATOMIC_RELAXED);
        } else {
            conn->last_server_tsc = now;
            conn->packets_s2c++;
            conn->bytes_s2c += features->packet_size;
            __atomic_add_fetch(&g_stats_v6.packets_proxied_s2c, 1, __ATOMIC_RELAXED);
        }

        /* Handle RST/FIN */
        if (tcp_flags & (TCP_FLAG_RST | TCP_FLAG_FIN)) {
            syn_proxy_v6_close_connection(key.client_ip, key.server_ip,
                                           key.client_port, key.server_port);
        }

        result->action = SYN_PROXY_FORWARD;
        return 0;
    }

    /* No connection, not SYN - forward */
    result->action = SYN_PROXY_FORWARD;
    return 0;
}

bool syn_proxy_v6_is_proxied(const struct packet_features_v6 *features,
                             uint8_t direction __rte_unused)
{
    if (!g_conn_table_v6 || !features) return false;

    struct conn_key_v6 key;
    rte_memcpy(key.client_ip, features->src_ip.v6, 16);
    rte_memcpy(key.server_ip, features->dst_ip.v6, 16);
    key.client_port = features->src_port;
    key.server_port = features->dst_port;

    return rte_hash_lookup(g_conn_table_v6, &key) >= 0;
}

int syn_proxy_v6_close_connection(const uint8_t client_ip[16],
                                  const uint8_t server_ip[16],
                                  uint16_t client_port,
                                  uint16_t server_port)
{
    if (!g_conn_table_v6) return -1;

    struct conn_key_v6 key;
    rte_memcpy(key.client_ip, client_ip, 16);
    rte_memcpy(key.server_ip, server_ip, 16);
    key.client_port = client_port;
    key.server_port = server_port;

    int ret = rte_hash_del_key(g_conn_table_v6, &key);
    if (ret >= 0) {
        __atomic_add_fetch(&g_stats_v6.connections_closed, 1, __ATOMIC_RELAXED);
        __atomic_sub_fetch(&g_stats_v6.connections_active, 1, __ATOMIC_RELAXED);
    }

    return (ret >= 0) ? 0 : -1;
}

uint32_t syn_proxy_v6_cleanup_connections(void)
{
    /* TODO: Implement connection timeout scanning */
    return 0;
}

void syn_proxy_v6_rotate_secret(uint32_t new_secret)
{
    rte_memcpy(g_secret_prev_v6, g_secret_v6, sizeof(g_secret_v6));

    g_secret_v6[0] = new_secret;
    g_secret_v6[1] = new_secret ^ 0x12345678;
    g_secret_v6[2] = new_secret ^ 0x9abcdef0;
    g_secret_v6[3] = new_secret ^ 0xfedcba98;

    g_secret_rotation_tsc = rte_rdtsc();

    RTE_LOG(DEBUG, SYN_PROXY_V6, "IPv6 SYN cookie secret rotated\n");
}

bool syn_proxy_v6_should_challenge(const struct packet_features_v6 *features __rte_unused)
{
    /* In stateless mode, always challenge SYN packets */
    if (g_forced_mode_v6 == SYN_PROXY_MODE_STATELESS ||
        g_current_mode_v6 == SYN_PROXY_MODE_STATELESS) {
        return true;
    }

    /* In adaptive mode, challenge based on current SYN rate */
    return (g_current_syn_rate_v6 > g_config_v6.stateless_threshold_pps);
}

/* ==================== Statistics ==================== */

void syn_proxy_v6_get_stats(struct syn_proxy_stats_v6 *stats)
{
    if (!stats) return;
    rte_memcpy(stats, &g_stats_v6, sizeof(*stats));
    stats->current_mode = g_current_mode_v6;
    stats->current_syn_rate = g_current_syn_rate_v6;
}

void syn_proxy_v6_reset_stats(void)
{
    uint32_t active = g_stats_v6.connections_active;
    memset(&g_stats_v6, 0, sizeof(g_stats_v6));
    g_stats_v6.connections_active = active;
}

void syn_proxy_v6_print_stats(void)
{
    RTE_LOG(INFO, SYN_PROXY_V6,
            "IPv6 SYN Proxy: active=%u created=%"PRIu64" established=%"PRIu64" "
            "cookies_sent=%"PRIu64" valid=%"PRIu64" invalid=%"PRIu64"\n",
            g_stats_v6.connections_active,
            g_stats_v6.connections_created,
            g_stats_v6.connections_established,
            g_stats_v6.cookies_sent,
            g_stats_v6.cookies_valid,
            g_stats_v6.cookies_invalid);
}

enum syn_proxy_mode syn_proxy_v6_get_mode(void)
{
    return g_current_mode_v6;
}

void syn_proxy_v6_set_mode(int mode)
{
    g_forced_mode_v6 = mode;
    if (mode >= 0) {
        g_current_mode_v6 = (enum syn_proxy_mode)mode;
    }
}

/* ==================== Dual-Stack API ==================== */

int syn_proxy_process_unified(struct rte_mbuf *m,
                              bool is_ipv6,
                              void *features,
                              uint8_t direction,
                              struct rte_mempool *mempool,
                              struct syn_proxy_result *result,
                              uint16_t port_id)
{
    if (is_ipv6) {
        struct syn_proxy_result_v6 result_v6;
        int ret = syn_proxy_v6_process_packet(m,
                                              (struct packet_features_v6 *)features,
                                              direction, mempool, &result_v6, port_id);
        if (result) {
            result->action = result_v6.action;
            result->packet_modified = result_v6.packet_modified;
            result->reply_pkt = result_v6.reply_pkt;
            result->conn_state = result_v6.conn_state;
            result->conn_id = result_v6.conn_id;
        }
        return ret;
    } else {
        return syn_proxy_process_packet(m, (struct packet_features *)features,
                                         direction, mempool, result, port_id, NULL);
    }
}

bool syn_proxy_is_proxied_unified(const void *features, bool is_ipv6,
                                  uint8_t direction)
{
    if (is_ipv6) {
        return syn_proxy_v6_is_proxied((const struct packet_features_v6 *)features,
                                       direction);
    } else {
        return syn_proxy_is_proxied((const struct packet_features *)features,
                                    direction);
    }
}
