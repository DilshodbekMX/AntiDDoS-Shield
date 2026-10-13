#include "window_stats.h"
#include <rte_log.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <time.h>

#define RTE_LOGTYPE_WSTATS RTE_LOGTYPE_USER3

// ==================== Global State ====================

static void *shm_base = NULL;
static size_t shm_size = 0;
static int shm_fd = -1;
static bool initialized = false;

// Pointers into shared memory
static struct window_shm_header *shm_header = NULL;
static struct lcore_window_accum *lcore_accums = NULL;
static struct window_sample *sample_ring = NULL;
static struct window_stats *window_1s = NULL;
static struct window_stats *window_10s = NULL;
static struct window_stats *window_60s = NULL;

// Cardinality snapshots (set externally, used during tick)
static uint64_t g_unique_src_ips = 0;
static uint64_t g_unique_dst_ports = 0;
static uint64_t g_active_flows = 0;

// ==================== Helper Functions ====================

static inline void add_counters(struct window_counters *dst,
                                const struct window_counters *src) {
    dst->total_packets += src->total_packets;
    dst->total_bytes += src->total_bytes;
    dst->packets_accepted += src->packets_accepted;
    dst->packets_dropped += src->packets_dropped;
    dst->inbound_packets += src->inbound_packets;
    dst->inbound_bytes += src->inbound_bytes;
    dst->outbound_packets += src->outbound_packets;
    dst->outbound_bytes += src->outbound_bytes;
    dst->tcp_packets += src->tcp_packets;
    dst->udp_packets += src->udp_packets;
    dst->icmp_packets += src->icmp_packets;
    dst->other_proto_packets += src->other_proto_packets;
    dst->syn_packets += src->syn_packets;
    dst->syn_ack_packets += src->syn_ack_packets;
    dst->ack_packets += src->ack_packets;
    dst->rst_packets += src->rst_packets;
    dst->fin_packets += src->fin_packets;
    dst->psh_packets += src->psh_packets;
    dst->drop_validation += src->drop_validation;
    dst->drop_blacklist += src->drop_blacklist;
    dst->drop_rate_limit += src->drop_rate_limit;
    dst->drop_syn_flood += src->drop_syn_flood;
    dst->drop_reputation += src->drop_reputation;
    dst->drop_policy += src->drop_policy;
    dst->syn_proxy_challenges += src->syn_proxy_challenges;
    dst->syn_proxy_established += src->syn_proxy_established;
    dst->cookies_sent += src->cookies_sent;
    dst->cookies_valid += src->cookies_valid;
    dst->cookies_invalid += src->cookies_invalid;
    dst->new_flows += src->new_flows;
    dst->aged_flows += src->aged_flows;
    // active_flows, unique_* are snapshots, take latest
    dst->pkt_size_0_64 += src->pkt_size_0_64;
    dst->pkt_size_65_128 += src->pkt_size_65_128;
    dst->pkt_size_129_256 += src->pkt_size_129_256;
    dst->pkt_size_257_512 += src->pkt_size_257_512;
    dst->pkt_size_513_1024 += src->pkt_size_513_1024;
    dst->pkt_size_1025_1518 += src->pkt_size_1025_1518;
    dst->pkt_size_jumbo += src->pkt_size_jumbo;
}

static void compute_rates(struct window_stats *ws) {
    double seconds = (double)ws->window_seconds;
    if (seconds <= 0) seconds = 1.0;

    struct window_counters *c = &ws->counters;
    struct window_rates *r = &ws->rates;

    // PPS
    r->pps_total = (double)c->total_packets / seconds;
    r->pps_inbound = (double)c->inbound_packets / seconds;
    r->pps_outbound = (double)c->outbound_packets / seconds;
    r->pps_tcp = (double)c->tcp_packets / seconds;
    r->pps_udp = (double)c->udp_packets / seconds;
    r->pps_syn = (double)c->syn_packets / seconds;
    r->pps_dropped = (double)c->packets_dropped / seconds;

    // BPS
    r->bps_total = (double)c->total_bytes * 8.0 / seconds;
    r->bps_inbound = (double)c->inbound_bytes * 8.0 / seconds;
    r->bps_outbound = (double)c->outbound_bytes * 8.0 / seconds;

    // Ratios
    r->syn_to_synack_ratio = (c->syn_ack_packets > 0) ?
        (double)c->syn_packets / (double)c->syn_ack_packets : 0.0;

    r->syn_to_ack_ratio = (c->ack_packets > 0) ?
        (double)c->syn_packets / (double)c->ack_packets : 0.0;

    r->rst_ratio = (c->total_packets > 0) ?
        (double)c->rst_packets / (double)c->total_packets : 0.0;

    r->small_pkt_ratio = (c->total_packets > 0) ?
        (double)c->pkt_size_0_64 / (double)c->total_packets : 0.0;

    r->drop_ratio = (c->total_packets > 0) ?
        (double)c->packets_dropped / (double)c->total_packets : 0.0;

    r->new_flow_rate = (double)c->new_flows / seconds;
}

static void aggregate_window(struct window_stats *ws,
                             uint32_t window_seconds,
                             uint32_t current_idx,
                             uint32_t samples_valid) {
    memset(ws, 0, sizeof(*ws));
    ws->window_seconds = window_seconds;

    uint32_t samples_to_use = (samples_valid < window_seconds) ?
                               samples_valid : window_seconds;
    ws->samples_used = samples_to_use;

    if (samples_to_use == 0) {
        return;
    }

    // Sum samples from ring buffer
    for (uint32_t i = 0; i < samples_to_use; i++) {
        // Go backwards from current index
        uint32_t idx = (current_idx - i + SAMPLE_RING_SIZE) % SAMPLE_RING_SIZE;
        struct window_sample *sample = &sample_ring[idx];

        if (i == 0) {
            ws->end_timestamp = sample->timestamp_sec;
        }
        if (i == samples_to_use - 1) {
            ws->start_timestamp = sample->timestamp_sec;
        }

        add_counters(&ws->counters, &sample->counters);
    }

    // Use latest cardinality snapshots
    ws->counters.unique_src_ips = g_unique_src_ips;
    ws->counters.unique_dst_ports = g_unique_dst_ports;
    ws->counters.active_flows = g_active_flows;

    // Compute derived rates
    compute_rates(ws);

    // Multi-window characterization (paper section 4.1.3): pulsing (pps variance) and ramping (least-
    // squares trend slope) over the per-second pps series in this window. Each ring sample covers
    // one second, so total_packets per sample is that second's pps. Telemetry only -- the production
    // ensemble does not threshold these directly (a fixed CV/slope rule fires on bursty benign,
    // section 6.8, [34]); they feed the calibrated conformal path. Variance uses the numerically stable
    // two-pass form; the slope is gated on R^2 to reject high-leverage endpoint bursts, matching
    // experiment/multiwindow.py for harness/C fidelity.
    ws->rates.pps_variance = 0.0;
    ws->rates.pps_trend_slope = 0.0;
    if (samples_to_use >= 2) {
        uint32_t n = samples_to_use;
        // Pass 1: mean.
        double sum_x = 0.0;
        for (uint32_t i = 0; i < n; i++) {
            uint32_t idx = (current_idx - i + SAMPLE_RING_SIZE) % SAMPLE_RING_SIZE;
            sum_x += (double)sample_ring[idx].counters.total_packets;
        }
        double mean = sum_x / n;
        // Pass 2: centered moments (stable variance + regression terms). t = 0..n-1 oldest..newest.
        double ss_x = 0.0;            // Sum (x-mean)^2
        double s_t = 0.0, s_tt = 0.0, s_tx = 0.0;
        for (uint32_t i = 0; i < n; i++) {
            uint32_t idx = (current_idx - i + SAMPLE_RING_SIZE) % SAMPLE_RING_SIZE;
            double x = (double)sample_ring[idx].counters.total_packets;
            double dx = x - mean;
            double t = (double)(n - 1 - i);
            ss_x += dx * dx;
            s_t += t; s_tt += t * t; s_tx += t * x;
        }
        ws->rates.pps_variance = ss_x / n;
        double denom = (double)n * s_tt - s_t * s_t;
        if (denom != 0.0) {
            double slope = ((double)n * s_tx - s_t * sum_x) / denom;
            // R^2 = cov(t,x)^2 / (var(t)*var(x)); reject low-fit (bursty) windows.
            double cov = s_tx / n - (s_t / n) * mean;
            double var_t = s_tt / n - (s_t / n) * (s_t / n);
            double var_x = ss_x / n;
            double r2 = (var_t > 0.0 && var_x > 0.0) ? (cov * cov) / (var_t * var_x) : 0.0;
            ws->rates.pps_trend_slope = (r2 >= 0.5) ? slope : 0.0;
        }
    }
}

// ==================== Initialization ====================

int window_stats_init(void) {
    if (initialized) {
        RTE_LOG(WARNING, WSTATS, "Already initialized\n");
        return 0;
    }

    // Calculate sizes
    size_t header_size = sizeof(struct window_shm_header);
    size_t lcore_size = sizeof(struct lcore_window_accum) * WS_MAX_LCORES;
    size_t ring_size = sizeof(struct window_sample) * SAMPLE_RING_SIZE;
    size_t window_size = sizeof(struct window_stats) * 3;  // 1s, 10s, 60s

    shm_size = header_size + lcore_size + ring_size + window_size;

    // Round up to page size
    long page_size = sysconf(_SC_PAGESIZE);
    shm_size = ((shm_size + page_size - 1) / page_size) * page_size;

    RTE_LOG(INFO, WSTATS, "Creating window stats shared memory: %zu bytes\n", shm_size);

    // Create shared memory
    shm_fd = open(WINDOW_SHM_PATH, O_CREAT | O_RDWR | O_TRUNC, 0644);
    if (shm_fd < 0) {
        RTE_LOG(ERR, WSTATS, "Failed to create %s: %s\n",
                WINDOW_SHM_PATH, strerror(errno));
        return -1;
    }

    if (ftruncate(shm_fd, shm_size) < 0) {
        RTE_LOG(ERR, WSTATS, "Failed to set size: %s\n", strerror(errno));
        close(shm_fd);
        unlink(WINDOW_SHM_PATH);
        return -1;
    }

    shm_base = mmap(NULL, shm_size, PROT_READ | PROT_WRITE,
                    MAP_SHARED, shm_fd, 0);
    if (shm_base == MAP_FAILED) {
        RTE_LOG(ERR, WSTATS, "Failed to mmap: %s\n", strerror(errno));
        close(shm_fd);
        unlink(WINDOW_SHM_PATH);
        return -1;
    }

    memset(shm_base, 0, shm_size);

    // Set up pointers
    uint8_t *ptr = (uint8_t *)shm_base;

    shm_header = (struct window_shm_header *)ptr;
    ptr += header_size;

    lcore_accums = (struct lcore_window_accum *)ptr;
    ptr += lcore_size;

    sample_ring = (struct window_sample *)ptr;
    ptr += ring_size;

    window_1s = (struct window_stats *)ptr;
    ptr += sizeof(struct window_stats);

    window_10s = (struct window_stats *)ptr;
    ptr += sizeof(struct window_stats);

    window_60s = (struct window_stats *)ptr;

    // Initialize header
    shm_header->magic = WINDOW_SHM_MAGIC;
    shm_header->version = WINDOW_SHM_VERSION;
    shm_header->num_lcores = rte_lcore_count();
    shm_header->tsc_hz = rte_get_tsc_hz();
    shm_header->creation_time = time(NULL);
    shm_header->current_sample_idx = 0;
    shm_header->samples_valid = 0;

    // Store offsets
    shm_header->lcore_accum_offset = (uint8_t *)lcore_accums - (uint8_t *)shm_base;
    shm_header->sample_ring_offset = (uint8_t *)sample_ring - (uint8_t *)shm_base;
    shm_header->window_1s_offset = (uint8_t *)window_1s - (uint8_t *)shm_base;
    shm_header->window_10s_offset = (uint8_t *)window_10s - (uint8_t *)shm_base;
    shm_header->window_60s_offset = (uint8_t *)window_60s - (uint8_t *)shm_base;

    __atomic_thread_fence(__ATOMIC_RELEASE);

    initialized = true;

    RTE_LOG(INFO, WSTATS, "Window stats initialized:\n");
    RTE_LOG(INFO, WSTATS, "  Path: %s\n", WINDOW_SHM_PATH);
    RTE_LOG(INFO, WSTATS, "  Windows: 1s, 10s, 60s\n");
    RTE_LOG(INFO, WSTATS, "  Sample ring: %d entries\n", SAMPLE_RING_SIZE);

    return 0;
}

void window_stats_cleanup(void) {
    if (!initialized) {
        return;
    }

    RTE_LOG(INFO, WSTATS, "Cleaning up window stats\n");

    if (shm_base && shm_base != MAP_FAILED) {
        munmap(shm_base, shm_size);
        shm_base = NULL;
    }

    if (shm_fd >= 0) {
        close(shm_fd);
        shm_fd = -1;
    }

    shm_header = NULL;
    lcore_accums = NULL;
    sample_ring = NULL;
    window_1s = NULL;
    window_10s = NULL;
    window_60s = NULL;

    initialized = false;
}

// ==================== Fast Path Updates ====================

void window_stats_update_packet(uint16_t pkt_size,
                                 uint8_t protocol,
                                 uint8_t tcp_flags,
                                 uint8_t direction,
                                 bool accepted,
                                 uint8_t drop_reason) {
    if (!initialized || !lcore_accums) {
        return;
    }

    unsigned int lcore_id = rte_lcore_id();
    if (lcore_id >= WS_MAX_LCORES) {
        lcore_id = 0;
    }

    struct window_counters *c = &lcore_accums[lcore_id].counters;

    // Volume
    c->total_packets++;
    c->total_bytes += pkt_size;

    if (accepted) {
        c->packets_accepted++;
    } else {
        c->packets_dropped++;

        // Drop reason breakdown
        switch (drop_reason) {
            case 1: c->drop_validation++; break;
            case 2: c->drop_blacklist++; break;
            case 3: c->drop_rate_limit++; break;
            case 4: c->drop_syn_flood++; break;
            case 5: c->drop_reputation++; break;
            case 6: c->drop_policy++; break;
        }
    }

    // Direction
    if (direction == 0) {
        c->inbound_packets++;
        c->inbound_bytes += pkt_size;
    } else {
        c->outbound_packets++;
        c->outbound_bytes += pkt_size;
    }

    // Protocol
    switch (protocol) {
        case IPPROTO_TCP:
            c->tcp_packets++;
            // TCP flags
            if (tcp_flags & 0x02) c->syn_packets++;      // SYN
            if ((tcp_flags & 0x12) == 0x12) c->syn_ack_packets++;  // SYN+ACK
            if (tcp_flags & 0x10) c->ack_packets++;      // ACK
            if (tcp_flags & 0x04) c->rst_packets++;      // RST
            if (tcp_flags & 0x01) c->fin_packets++;      // FIN
            if (tcp_flags & 0x08) c->psh_packets++;      // PSH
            break;
        case IPPROTO_UDP:
            c->udp_packets++;
            break;
        case IPPROTO_ICMP:
            c->icmp_packets++;
            break;
        default:
            c->other_proto_packets++;
            break;
    }

    // Packet size distribution
    if (pkt_size <= 64) {
        c->pkt_size_0_64++;
    } else if (pkt_size <= 128) {
        c->pkt_size_65_128++;
    } else if (pkt_size <= 256) {
        c->pkt_size_129_256++;
    } else if (pkt_size <= 512) {
        c->pkt_size_257_512++;
    } else if (pkt_size <= 1024) {
        c->pkt_size_513_1024++;
    } else if (pkt_size <= 1518) {
        c->pkt_size_1025_1518++;
    } else {
        c->pkt_size_jumbo++;
    }
}

void window_stats_update_syn_proxy(bool challenge_sent,
                                    bool established,
                                    bool cookie_valid,
                                    bool cookie_invalid) {
    if (!initialized || !lcore_accums) {
        return;
    }

    unsigned int lcore_id = rte_lcore_id();
    if (lcore_id >= WS_MAX_LCORES) {
        lcore_id = 0;
    }

    struct window_counters *c = &lcore_accums[lcore_id].counters;

    if (challenge_sent) {
        c->syn_proxy_challenges++;
        c->cookies_sent++;
    }
    if (established) {
        c->syn_proxy_established++;
    }
    if (cookie_valid) {
        c->cookies_valid++;
    }
    if (cookie_invalid) {
        c->cookies_invalid++;
    }
}

void window_stats_update_flow(bool new_flow, bool aged_flow) {
    if (!initialized || !lcore_accums) {
        return;
    }

    unsigned int lcore_id = rte_lcore_id();
    if (lcore_id >= WS_MAX_LCORES) {
        lcore_id = 0;
    }

    struct window_counters *c = &lcore_accums[lcore_id].counters;

    if (new_flow) c->new_flows++;
    if (aged_flow) c->aged_flows++;
}

void window_stats_set_cardinality(uint64_t unique_src_ips,
                                   uint64_t unique_dst_ports,
                                   uint64_t active_flows) {
    g_unique_src_ips = unique_src_ips;
    g_unique_dst_ports = unique_dst_ports;
    g_active_flows = active_flows;
}

// ==================== Tick Function ====================

void window_stats_tick(void) {
    if (!initialized) {
        return;
    }

    // Aggregate all lcore counters into a single sample
    struct window_counters aggregated;
    memset(&aggregated, 0, sizeof(aggregated));

    for (unsigned int i = 0; i < WS_MAX_LCORES; i++) {
        add_counters(&aggregated, &lcore_accums[i].counters);
        // Reset lcore counters
        memset(&lcore_accums[i].counters, 0, sizeof(struct window_counters));
    }

    // Add cardinality snapshots
    aggregated.unique_src_ips = g_unique_src_ips;
    aggregated.unique_dst_ports = g_unique_dst_ports;
    aggregated.active_flows = g_active_flows;

    // Store sample in ring buffer
    uint32_t idx = shm_header->current_sample_idx;
    sample_ring[idx].timestamp_sec = time(NULL);
    sample_ring[idx].timestamp_tsc = rte_rdtsc();
    memcpy(&sample_ring[idx].counters, &aggregated, sizeof(aggregated));

    // Advance ring index
    shm_header->current_sample_idx = (idx + 1) % SAMPLE_RING_SIZE;
    if (shm_header->samples_valid < SAMPLE_RING_SIZE) {
        shm_header->samples_valid++;
    }

    // Compute window aggregations
    uint32_t current_idx = idx;  // Use the sample we just wrote
    uint32_t samples_valid = shm_header->samples_valid;

    aggregate_window(window_1s, 1, current_idx, samples_valid);
    aggregate_window(window_10s, 10, current_idx, samples_valid);
    aggregate_window(window_60s, 60, current_idx, samples_valid);

    // Update sequence number
    __atomic_add_fetch(&shm_header->update_sequence, 1, __ATOMIC_RELEASE);
}

// ==================== Accessor Functions ====================

int window_stats_get(uint32_t window_sec, struct window_stats *stats) {
    if (!initialized || !stats) {
        return -1;
    }

    struct window_stats *src = NULL;
    switch (window_sec) {
        case 1:  src = window_1s;  break;
        case 10: src = window_10s; break;
        case 60: src = window_60s; break;
        default: return -1;
    }

    memcpy(stats, src, sizeof(*stats));
    return 0;
}

void *window_stats_get_shm(void) {
    return initialized ? shm_base : NULL;
}

size_t window_stats_get_shm_size(void) {
    return shm_size;
}
