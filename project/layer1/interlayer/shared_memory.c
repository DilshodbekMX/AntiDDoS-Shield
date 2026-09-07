#include "shared_memory.h"
#include "../tables/flow_table.h"  // For flow_table_get_stats()
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_spinlock.h>
#include <rte_cycles.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <math.h>  // For log2() in entropy calculation

#define RTE_LOGTYPE_SHMEM RTE_LOGTYPE_USER6

// Forward declaration (defined below, used by anomaly_set_level)
static uint64_t get_timestamp_ns(void);

// ==================== Global State ====================

struct layer1_shared_memory *shared_mem = NULL;
static rte_spinlock_t init_lock = RTE_SPINLOCK_INITIALIZER;
static bool using_posix_shmem = false;
static int posix_shmem_fd = -1;

// ==================== Initialization ====================

int shared_memory_init(void) {
    rte_spinlock_lock(&init_lock);
    
    if (shared_mem != NULL) {
        rte_spinlock_unlock(&init_lock);
        RTE_LOG(WARNING, SHMEM, "Shared memory already initialized\n");
        return 0;
    }

    // Allocate shared memory on the current NUMA socket
    // In production, this would be true shared memory (shm_open, mmap)
    // For now, we use DPDK huge pages which can be accessed by multiple processes
    shared_mem = rte_zmalloc_socket("layer1_shmem",
                                    sizeof(struct layer1_shared_memory),
                                    4096,  // Page-aligned
                                    rte_socket_id());

    if (!shared_mem) {
        rte_spinlock_unlock(&init_lock);
        RTE_LOG(ERR, SHMEM, "Failed to allocate shared memory\n");
        return -1;
    }

    // Initialize policy table
    __atomic_store_n(&shared_mem->policies.count, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&shared_mem->policies.global_version, 0, __ATOMIC_RELAXED);

    // Initialize reputation table
    __atomic_store_n(&shared_mem->reputation.count, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&shared_mem->reputation.global_version, 0, __ATOMIC_RELAXED);

    // Initialize feedback queue
    __atomic_store_n(&shared_mem->feedback.head, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&shared_mem->feedback.tail, 0, __ATOMIC_RELAXED);

    // Initialize global state
    __atomic_store_n(&shared_mem->state.anomaly_active, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&shared_mem->state.anomaly_level, ANOMALY_LEVEL_NONE, __ATOMIC_RELAXED);
    __atomic_store_n(&shared_mem->state.rate_limit_pct, 100, __ATOMIC_RELAXED);
    __atomic_store_n(&shared_mem->state.total_pps, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&shared_mem->state.total_bps, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&shared_mem->state.baseline_pps, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&shared_mem->state.baseline_bps, 0, __ATOMIC_RELAXED);

    // Full memory barrier to ensure all initialization is visible
    rte_smp_wmb();

    rte_spinlock_unlock(&init_lock);

    RTE_LOG(INFO, SHMEM, "Shared memory initialized:\n");
    RTE_LOG(INFO, SHMEM, "  Total size: %lu bytes (~%.1f MB)\n",
            sizeof(struct layer1_shared_memory),
            sizeof(struct layer1_shared_memory) / (1024.0 * 1024.0));
    RTE_LOG(INFO, SHMEM, "  Max policies: %d\n", MAX_POLICIES);
    RTE_LOG(INFO, SHMEM, "  Max reputation entries: %d\n", MAX_REPUTATION_ENTRIES);
    RTE_LOG(INFO, SHMEM, "  Max feedback events: %d\n", MAX_FEEDBACK_EVENTS);

    return 0;
}

void shared_memory_cleanup(void) {
    rte_spinlock_lock(&init_lock);

    if (shared_mem) {
        if (using_posix_shmem) {
            // Unmap POSIX shared memory
            munmap(shared_mem, POSIX_SHMEM_SIZE);
            if (posix_shmem_fd >= 0) {
                close(posix_shmem_fd);
                posix_shmem_fd = -1;
            }
            // Remove shared memory file
            shm_unlink(POSIX_SHMEM_NAME);
            RTE_LOG(INFO, SHMEM, "POSIX shared memory cleanup complete\n");
        } else {
            rte_free(shared_mem);
            RTE_LOG(INFO, SHMEM, "Shared memory cleanup complete\n");
        }
        shared_mem = NULL;
        using_posix_shmem = false;
    }

    rte_spinlock_unlock(&init_lock);
}

// ==================== POSIX Shared Memory Initialization ====================

int shared_memory_init_posix(void) {
    rte_spinlock_lock(&init_lock);

    if (shared_mem != NULL) {
        rte_spinlock_unlock(&init_lock);
        RTE_LOG(WARNING, SHMEM, "Shared memory already initialized\n");
        return 0;
    }

    // Use 0660 permissions instead of 0666
    // Only owner (root/dpdk) and group can read/write shared memory
    posix_shmem_fd = shm_open(POSIX_SHMEM_NAME, O_CREAT | O_RDWR, 0660);
    if (posix_shmem_fd < 0) {
        rte_spinlock_unlock(&init_lock);
        RTE_LOG(ERR, SHMEM, "Failed to create POSIX shared memory: %s\n", strerror(errno));
        return -1;
    }

    // Use 0660 instead of 0666
    // Backend process must be in same group as DPDK process to access
    if (fchmod(posix_shmem_fd, 0660) < 0) {
        RTE_LOG(WARNING, SHMEM, "Failed to set shared memory permissions: %s\n", strerror(errno));
        // Continue anyway - might work if umask is permissive
    }

    // Set size
    if (ftruncate(posix_shmem_fd, POSIX_SHMEM_SIZE) < 0) {
        close(posix_shmem_fd);
        shm_unlink(POSIX_SHMEM_NAME);
        rte_spinlock_unlock(&init_lock);
        RTE_LOG(ERR, SHMEM, "Failed to set shared memory size: %s\n", strerror(errno));
        return -1;
    }

    // Map to memory
    shared_mem = mmap(NULL, POSIX_SHMEM_SIZE, PROT_READ | PROT_WRITE,
                      MAP_SHARED, posix_shmem_fd, 0);
    if (shared_mem == MAP_FAILED) {
        shared_mem = NULL;
        close(posix_shmem_fd);
        shm_unlink(POSIX_SHMEM_NAME);
        rte_spinlock_unlock(&init_lock);
        RTE_LOG(ERR, SHMEM, "Failed to mmap shared memory: %s\n", strerror(errno));
        return -1;
    }

    using_posix_shmem = true;

    // Initialize shared memory content (same as regular init)
    memset(shared_mem, 0, POSIX_SHMEM_SIZE);

    // Write shmem header for Python ABI validation
    shared_mem->header.magic = SHMEM_MAGIC;
    shared_mem->header.version = SHMEM_ABI_VERSION;
    shared_mem->header.size = POSIX_SHMEM_SIZE;
    shared_mem->header.created_tsc = rte_get_tsc_cycles();
    shared_mem->header.tsc_hz = rte_get_tsc_hz();

    // Initialize policy table
    __atomic_store_n(&shared_mem->policies.count, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&shared_mem->policies.global_version, 0, __ATOMIC_RELAXED);

    // Initialize reputation table
    __atomic_store_n(&shared_mem->reputation.count, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&shared_mem->reputation.global_version, 0, __ATOMIC_RELAXED);

    // Initialize feedback queue
    __atomic_store_n(&shared_mem->feedback.head, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&shared_mem->feedback.tail, 0, __ATOMIC_RELAXED);

    // Initialize global state
    __atomic_store_n(&shared_mem->state.anomaly_active, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&shared_mem->state.anomaly_level, ANOMALY_LEVEL_NONE, __ATOMIC_RELAXED);
    __atomic_store_n(&shared_mem->state.rate_limit_pct, 100, __ATOMIC_RELAXED);
    __atomic_store_n(&shared_mem->state.total_pps, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&shared_mem->state.total_bps, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&shared_mem->state.baseline_pps, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&shared_mem->state.baseline_bps, 0, __ATOMIC_RELAXED);

    // Full memory barrier
    rte_smp_wmb();

    rte_spinlock_unlock(&init_lock);

    RTE_LOG(INFO, SHMEM, "POSIX shared memory initialized:\n");
    RTE_LOG(INFO, SHMEM, "  Path: /dev/shm%s\n", POSIX_SHMEM_NAME);
    RTE_LOG(INFO, SHMEM, "  Size: %lu bytes (~%.1f MB)\n",
            (unsigned long)POSIX_SHMEM_SIZE, POSIX_SHMEM_SIZE / (1024.0 * 1024.0));
    RTE_LOG(INFO, SHMEM, "  Max policies: %d\n", MAX_POLICIES);
    RTE_LOG(INFO, SHMEM, "  Max reputation entries: %d\n", MAX_REPUTATION_ENTRIES);
    RTE_LOG(INFO, SHMEM, "  Python can access via: mmap.mmap(os.open('/dev/shm%s', os.O_RDWR), %lu)\n",
            POSIX_SHMEM_NAME, (unsigned long)POSIX_SHMEM_SIZE);

    return 0;
}

bool shared_memory_is_posix(void) {
    return using_posix_shmem;
}

const char *shared_memory_get_path(void) {
    return using_posix_shmem ? "/dev/shm" POSIX_SHMEM_NAME : NULL;
}

struct layer1_shared_memory *shared_memory_get(void) {
    // Read with acquire semantics to ensure we see initialized data
    rte_smp_rmb();
    return shared_mem;
}

// ==================== Anomaly State API ====================

bool anomaly_is_active(void) {
    if (!shared_mem) return false;
    return __atomic_load_n(&shared_mem->state.anomaly_active, __ATOMIC_ACQUIRE) != 0;
}

uint32_t anomaly_get_level(void) {
    if (!shared_mem) return ANOMALY_LEVEL_NONE;
    return __atomic_load_n(&shared_mem->state.anomaly_level, __ATOMIC_ACQUIRE);
}

void anomaly_set_level(uint32_t level) {
    if (!shared_mem) return;

    uint32_t old_level = __atomic_load_n(&shared_mem->state.anomaly_level, __ATOMIC_ACQUIRE);

    if (level > ANOMALY_LEVEL_CRITICAL) {
        level = ANOMALY_LEVEL_CRITICAL;
    }

    __atomic_store_n(&shared_mem->state.anomaly_level, level, __ATOMIC_RELEASE);

    if (level > ANOMALY_LEVEL_NONE) {
        __atomic_store_n(&shared_mem->state.anomaly_active, 1, __ATOMIC_RELEASE);

        // Use get_timestamp_ns() (not rte_get_tsc_cycles) for _ns field
        if (old_level == ANOMALY_LEVEL_NONE) {
            __atomic_store_n(&shared_mem->state.anomaly_start_ns,
                             get_timestamp_ns(), __ATOMIC_RELAXED);
        }

        // Calculate rate limit percentage based on level
        // Level 1 (low):      80% of normal
        // Level 2 (medium):   50% of normal
        // Level 3 (high):     25% of normal
        // Level 4 (critical): 10% of normal
        uint32_t rate_pct;
        switch (level) {
            case ANOMALY_LEVEL_LOW:      rate_pct = 80; break;
            case ANOMALY_LEVEL_MEDIUM:   rate_pct = 50; break;
            case ANOMALY_LEVEL_HIGH:     rate_pct = 25; break;
            case ANOMALY_LEVEL_CRITICAL: rate_pct = 10; break;
            default:                     rate_pct = 100; break;
        }
        __atomic_store_n(&shared_mem->state.rate_limit_pct, rate_pct, __ATOMIC_RELEASE);

        RTE_LOG(WARNING, SHMEM, "Anomaly level set to %u (rate limit: %u%%)\n", level, rate_pct);
    } else {
        __atomic_store_n(&shared_mem->state.anomaly_active, 0, __ATOMIC_RELEASE);
        __atomic_store_n(&shared_mem->state.rate_limit_pct, 100, __ATOMIC_RELEASE);
        RTE_LOG(INFO, SHMEM, "Anomaly cleared\n");
    }

    // Use get_timestamp_ns() for _ns field (not raw TSC cycles)
    __atomic_store_n(&shared_mem->state.last_anomaly_update_ns,
                     get_timestamp_ns(), __ATOMIC_RELAXED);
}

void anomaly_clear(void) {
    anomaly_set_level(ANOMALY_LEVEL_NONE);
}

void anomaly_set_spoofed_mode(uint32_t spoofed, uint32_t randomness_pct) {
    if (!shared_mem) return;

    __atomic_store_n(&shared_mem->state.spoofed_attack_mode, spoofed, __ATOMIC_RELEASE);
    __atomic_store_n(&shared_mem->state.randomness_pct, randomness_pct, __ATOMIC_RELEASE);

    if (spoofed) {
        RTE_LOG(WARNING, SHMEM, "Spoofed attack mode ENABLED (randomness: %u%%) - using behavioral signatures\n",
                randomness_pct);
    }
}

bool anomaly_is_spoofed_mode(void) {
    if (!shared_mem) return false;
    return __atomic_load_n(&shared_mem->state.spoofed_attack_mode, __ATOMIC_ACQUIRE) != 0;
}

uint32_t anomaly_get_randomness_pct(void) {
    if (!shared_mem) return 0;
    return __atomic_load_n(&shared_mem->state.randomness_pct, __ATOMIC_ACQUIRE);
}

uint32_t anomaly_get_rate_limit_pct(void) {
    if (!shared_mem) return 100;
    uint32_t pct = __atomic_load_n(&shared_mem->state.rate_limit_pct, __ATOMIC_ACQUIRE);
    return (pct > 0 && pct <= 100) ? pct : 100;
}

void anomaly_suppress_mitigation(void) {
    if (!shared_mem) return;
    __atomic_store_n(&shared_mem->state.rate_limit_pct, 100, __ATOMIC_RELEASE);
    __atomic_store_n(&shared_mem->state.spoofed_attack_mode, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&shared_mem->state.mitigation_active, 0, __ATOMIC_RELEASE);
}

void anomaly_set_mitigation_active(uint32_t active) {
    if (!shared_mem) return;
    __atomic_store_n(&shared_mem->state.mitigation_active, active, __ATOMIC_RELEASE);
}

void anomaly_set_rate_limit_pct(uint32_t pct) {
    if (!shared_mem) return;
    if (pct > 100) pct = 100;
    __atomic_store_n(&shared_mem->state.rate_limit_pct, pct, __ATOMIC_RELEASE);
}

bool mitigation_is_active(void) {
    if (!shared_mem) return false;
    return __atomic_load_n(&shared_mem->state.mitigation_active, __ATOMIC_ACQUIRE) != 0;
}

void anomaly_update_traffic_stats(uint64_t pps, uint64_t bps) {
    if (!shared_mem) return;

    __atomic_store_n(&shared_mem->state.total_pps, pps, __ATOMIC_RELAXED);
    __atomic_store_n(&shared_mem->state.total_bps, bps, __ATOMIC_RELAXED);
}

uint64_t anomaly_get_baseline_pps(void) {
    if (!shared_mem) return 0;
    return __atomic_load_n(&shared_mem->state.baseline_pps, __ATOMIC_RELAXED);
}

// ==================== Layer 2 Features Export ====================

#include "../telemetry/per_ip_features.h"
#include "../telemetry/hyperloglog.h"
#include "../../core/dpdk_core.h"
#include <time.h>

// Previous stats for rate calculation
static struct aggregated_stats l2_prev_stats;
static uint64_t l2_prev_timestamp_ns = 0;
static uint32_t l2_prev_aged_flows = 0;  // Track aged flows for expired_srcip_rate

static uint64_t get_timestamp_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

void l2_features_export_update(void) {
    if (!shared_mem) return;

    struct l2_features_export *l2f = &shared_mem->l2_features;
    struct aggregated_stats current;

    uint64_t now_ns = get_timestamp_ns();

    // Get aggregated counters from all lcores
    aggregate_lcore_stats(&current);

    // First call: seed previous stats and skip export to avoid
    // computing deltas from zero (which would include all traffic
    // accumulated since DPDK startup, poisoning baselines).
    if (l2_prev_timestamp_ns == 0) {
        l2_prev_stats = current;
        l2_prev_timestamp_ns = now_ns;
        l2_prev_aged_flows = 0;
        RTE_LOG(INFO, SHMEM, "L2 features export: seeded initial counters (skipping first cycle)\n");
        return;
    }

    uint64_t delta_ns = now_ns - l2_prev_timestamp_ns;
    if (delta_ns == 0) delta_ns = 1;

    // Seqlock: mark write in progress (odd version)
    uint64_t version = __atomic_load_n(&l2f->version, __ATOMIC_RELAXED);
    __atomic_store_n(&l2f->version, version + 1, __ATOMIC_RELEASE);
    rte_smp_wmb();

    // Get HLL-based cardinality from global hyperloglog module
    l2f->unique_src_ips = (uint32_t)hll_global_src_ip_count();

    // For per-IP features, aggregate across all protected IPs
    // This provides a system-wide view from per-IP tracking
    if (per_ip_features_is_initialized() && per_ip_features_count() > 0) {
        struct per_ip_feature_snapshot snapshots[100];
        uint32_t count = per_ip_features_snapshot_all(snapshots, 100);

        // Aggregate cardinality and concentration metrics across all protected IPs
        uint32_t total_unique_dst_ports = 0;
        uint32_t total_unique_flows = 0;
        int32_t total_src_ip_churn = 0;
        int32_t total_dst_port_churn = 0;
        uint32_t max_heavy_hitters = 0;

        for (uint32_t i = 0; i < count; i++) {
            total_unique_dst_ports += snapshots[i].unique_dst_ports;
            total_unique_flows += snapshots[i].unique_flows;
            total_src_ip_churn += snapshots[i].src_ip_churn;
            total_dst_port_churn += snapshots[i].dst_port_churn;
            if (snapshots[i].heavy_hitter_count > max_heavy_hitters) {
                max_heavy_hitters = snapshots[i].heavy_hitter_count;
            }
        }

        l2f->unique_dst_ports = total_unique_dst_ports;
        l2f->unique_flows = total_unique_flows;
        l2f->new_srcip_rate = total_src_ip_churn;
        l2f->dst_port_churn = total_dst_port_churn;
        l2f->heavy_hitter_count = (uint16_t)max_heavy_hitters;

        // NOTE: Window reset moved to l2_per_ip_features_export_update()
        // to avoid zeroing the rates before per-IP export runs
    } else {
        l2f->unique_dst_ports = 0;
        l2f->unique_flows = 0;
        l2f->new_srcip_rate = 0;
        l2f->dst_port_churn = 0;
        l2f->heavy_hitter_count = 0;
    }

    // Concentration metrics (placeholder - would need top-K tracking)
    l2f->max_flow_fraction = 0;
    l2f->topk_flow_share = 0;

    // Calculate deltas (rates)
    double delta_sec = delta_ns / 1000000000.0;

    uint64_t rx_diff = current.rx_packets - l2_prev_stats.rx_packets;
    uint64_t bytes_diff = current.rx_bytes - l2_prev_stats.rx_bytes;
    uint64_t flows_diff = current.l1_new_flows - l2_prev_stats.l1_new_flows;

    // Volume features
    l2f->timestamp_ns = now_ns;
    l2f->window_duration_ns = delta_ns;
    l2f->packets_per_sec = (uint64_t)(rx_diff / delta_sec);
    l2f->bytes_per_sec = (uint64_t)(bytes_diff / delta_sec);
    l2f->flows_per_sec = (uint32_t)(flows_diff / delta_sec);

    // TCP flag rates
    uint64_t syn_diff = current.l1_syn_packets - l2_prev_stats.l1_syn_packets;
    uint64_t synack_diff = current.l1_syn_ack_packets - l2_prev_stats.l1_syn_ack_packets;
    uint64_t ack_diff = current.l1_ack_packets - l2_prev_stats.l1_ack_packets;
    uint64_t rst_diff = current.l1_rst_packets - l2_prev_stats.l1_rst_packets;
    uint64_t fin_diff = current.l1_fin_packets - l2_prev_stats.l1_fin_packets;

    l2f->syn_per_sec = (uint32_t)(syn_diff / delta_sec);
    l2f->syn_ack_per_sec = (uint32_t)(synack_diff / delta_sec);
    l2f->ack_per_sec = (uint32_t)(ack_diff / delta_sec);
    l2f->rst_per_sec = (uint32_t)(rst_diff / delta_sec);
    l2f->fin_per_sec = (uint32_t)(fin_diff / delta_sec);

    // Protocol counts (this window)
    l2f->tcp_packets = (uint32_t)(current.l1_tcp_packets - l2_prev_stats.l1_tcp_packets);
    l2f->udp_packets = (uint32_t)(current.l1_udp_packets - l2_prev_stats.l1_udp_packets);
    l2f->icmp_packets = (uint32_t)(current.l1_icmp_packets - l2_prev_stats.l1_icmp_packets);
    l2f->other_packets = (uint32_t)(current.l1_other_packets - l2_prev_stats.l1_other_packets);

    // Protocol ratios
    uint64_t total_proto = l2f->tcp_packets + l2f->udp_packets + l2f->icmp_packets + l2f->other_packets;
    if (total_proto > 0) {
        l2f->tcp_ratio = (uint8_t)((l2f->tcp_packets * 100) / total_proto);
        l2f->udp_ratio = (uint8_t)((l2f->udp_packets * 100) / total_proto);
        l2f->icmp_ratio = (uint8_t)((l2f->icmp_packets * 100) / total_proto);
    } else {
        l2f->tcp_ratio = l2f->udp_ratio = l2f->icmp_ratio = 0;
    }

    // Ratio features
    l2f->syn_ack_ratio = (ack_diff > 0) ? (uint16_t)((syn_diff * 100) / ack_diff) : 0;
    l2f->rst_syn_ratio = (syn_diff > 0) ? (uint16_t)((rst_diff * 100) / syn_diff) : 0;
    l2f->bytes_per_packet = (rx_diff > 0) ? (uint16_t)(bytes_diff / rx_diff) : 0;

    // Flow behavior - integrate with flow table
    l2f->avg_packets_per_flow = (l2f->flows_per_sec > 0) ?
        (uint16_t)(l2f->packets_per_sec / l2f->flows_per_sec) : 0;

    // Get active flows from flow table
    uint32_t active_flows_count = 0;
    uint32_t total_flows_count = 0;
    uint32_t aged_flows_count = 0;
    flow_table_get_stats(&active_flows_count, &total_flows_count, &aged_flows_count);
    l2f->active_flows = active_flows_count;

    // Estimate average flow duration from completed flows in window
    // If we have new flows and aged flows, estimate duration based on window size
    if (aged_flows_count > 0 && delta_ns > 0) {
        // Rough estimate: flows that aged out were active for ~idle_timeout
        // Better estimate would require tracking flow lifetimes in flow table
        // For now, use window duration as approximation for short-lived flows
        l2f->flow_duration_avg_ms = (uint32_t)(delta_ns / 1000000);  // Window duration in ms
    } else if (l2f->flows_per_sec > 0 && active_flows_count > 0) {
        // Estimate: active_flows / flow_rate gives average lifetime
        l2f->flow_duration_avg_ms = (uint32_t)((active_flows_count * 1000) / l2f->flows_per_sec);
    } else {
        l2f->flow_duration_avg_ms = 0;
    }

    // Source IP entropy calculation
    // Entropy = log2(unique_src_ips) provides a measure of IP distribution diversity
    // Max entropy ~32 bits for IPv4, but practical max is ~20 bits (1M unique IPs)
    // Scaled to 0-255 where 255 = 8 bits of entropy (256 unique IPs evenly distributed)
    if (l2f->unique_src_ips > 1) {
        // Use log2 approximation: log2(x) = (31 - __builtin_clz(x)) for integers
        // More accurate: log2f for floating point
        double entropy_bits = log2((double)l2f->unique_src_ips);
        // Scale: 0-8 bits -> 0-255 (8 bits = max practical entropy for detection)
        uint32_t scaled = (uint32_t)((entropy_bits / 8.0) * 255.0);
        l2f->src_ip_entropy = (scaled > 255) ? 255 : (uint8_t)scaled;
    } else {
        l2f->src_ip_entropy = 0;  // Single IP or no traffic = no entropy
    }

    // TCP flag ratios (as % of TCP packets in this window)
    uint32_t tcp_pkt = l2f->tcp_packets;
    if (tcp_pkt > 0) {
        l2f->syn_tcp_ratio    = (uint8_t)((syn_diff * 100) / tcp_pkt);
        l2f->synack_tcp_ratio = (uint8_t)((synack_diff * 100) / tcp_pkt);
        l2f->ack_tcp_ratio    = (uint8_t)((ack_diff * 100) / tcp_pkt);
        l2f->rst_tcp_ratio    = (uint8_t)((rst_diff * 100) / tcp_pkt);
        l2f->fin_tcp_ratio    = (uint8_t)((fin_diff * 100) / tcp_pkt);
    } else {
        l2f->syn_tcp_ratio = l2f->synack_tcp_ratio = l2f->ack_tcp_ratio = 0;
        l2f->rst_tcp_ratio = l2f->fin_tcp_ratio = 0;
    }

    // Burst factor: current PPS / EWMA PPS * 100 (100 = normal, >200 = micro-burst)
    {
        static double ewma_pps = 0.0;
        double current_pps_d = (double)l2f->packets_per_sec;
        if (ewma_pps < 1.0)
            ewma_pps = current_pps_d;  // Seed on first call
        else
            ewma_pps = ewma_pps + 0.033 * (current_pps_d - ewma_pps);  // ~30s EWMA
        l2f->burst_factor = (ewma_pps > 0.0) ?
            (uint16_t)(current_pps_d * 100.0 / ewma_pps) : 100;
    }

    // UDP flow ratio: UDP_flows / UDP_PPS * 100
    {
        uint64_t udp_flows_diff = current.l1_new_udp_flows - l2_prev_stats.l1_new_udp_flows;
        uint32_t udp_pps = (l2f->udp_packets > 0) ?
            (uint32_t)((uint64_t)l2f->udp_packets / (uint64_t)(delta_sec > 0 ? delta_sec : 1)) : 0;
        l2f->udp_flow_ratio = (udp_pps > 0) ?
            (uint16_t)((udp_flows_diff * 100) / udp_pps) : 0;
    }

    // ICMP echo ratio: ICMP_echo / ICMP_total * 100
    {
        uint64_t icmp_echo_diff = current.l1_icmp_echo_packets - l2_prev_stats.l1_icmp_echo_packets;
        uint64_t icmp_total_diff = current.l1_icmp_packets - l2_prev_stats.l1_icmp_packets;
        l2f->icmp_echo_ratio = (icmp_total_diff > 0) ?
            (uint8_t)((icmp_echo_diff * 100) / icmp_total_diff) : 0;
    }

    // Dst port density: unique_dst_ports / PPS * 1000
    l2f->dst_port_density = (l2f->packets_per_sec > 0) ?
        (uint16_t)((uint64_t)l2f->unique_dst_ports * 1000 / l2f->packets_per_sec) : 0;

    // New L2 features (5)
    // small_pkt_ratio
    {
        uint64_t small_diff = current.l1_small_packets - l2_prev_stats.l1_small_packets;
        l2f->small_pkt_ratio = (rx_diff > 0) ? (uint8_t)((small_diff * 100) / rx_diff) : 0;
    }

    // tcp_completion_rate (SYN-ACK / SYN * 100, capped at 100)
    if (syn_diff > 0) {
        uint64_t comp = (synack_diff * 100) / syn_diff;
        l2f->tcp_completion_rate = (comp > 100) ? 100 : (uint8_t)comp;
    } else {
        l2f->tcp_completion_rate = 0;
    }

    // fragment_ratio
    {
        uint64_t frag_diff = current.l1_fragment_packets - l2_prev_stats.l1_fragment_packets;
        l2f->fragment_ratio = (rx_diff > 0) ? (uint8_t)((frag_diff * 100) / rx_diff) : 0;
    }

    // src_port_entropy (global src_port HLL not available; per-IP path provides this)
    l2f->src_port_entropy = 0;

    // ttl_mean
    {
        uint64_t ttl_sum_diff = current.l1_ttl_sum - l2_prev_stats.l1_ttl_sum;
        l2f->ttl_mean = (rx_diff > 0) ? (uint8_t)(ttl_sum_diff / rx_diff) : 0;
    }

    l2f->sample_count = (uint32_t)rx_diff;

    // Calculate expired source IP rate based on aged flows
    // Each aged flow represents at least one source IP that has gone quiet
    // This is an approximation - true tracking would require per-IP timeout monitoring
    uint32_t aged_diff = (aged_flows_count >= l2_prev_aged_flows) ?
                         (aged_flows_count - l2_prev_aged_flows) : 0;
    l2f->expired_srcip_rate = (delta_sec > 0) ? (int32_t)(aged_diff / delta_sec) : 0;
    l2_prev_aged_flows = aged_flows_count;

    // Memory barrier before publishing version
    rte_smp_wmb();

    // Seqlock: mark write complete (even version)
    __atomic_store_n(&l2f->version, version + 2, __ATOMIC_RELEASE);

    // Save for next iteration
    l2_prev_stats = current;
    l2_prev_timestamp_ns = now_ns;
}

void l2_features_export_reset(void) {
    memset(&l2_prev_stats, 0, sizeof(l2_prev_stats));
    l2_prev_timestamp_ns = 0;
    l2_prev_aged_flows = 0;
    if (shared_mem) {
        memset(&shared_mem->l2_features, 0, sizeof(shared_mem->l2_features));
    }
    RTE_LOG(INFO, SHMEM, "L2 features export reset (will re-seed on next cycle)\n");
}

struct l2_features_export *l2_features_export_get(void) {
    if (!shared_mem) return NULL;
    return &shared_mem->l2_features;
}

// ==================== Per-IP Features Export API ====================

void l2_per_ip_features_export_update(void) {
    if (!shared_mem) return;
    if (!per_ip_features_is_initialized()) return;

    struct l2_per_ip_export *per_ip = &shared_mem->l2_per_ip;

    // Seqlock: mark write in progress (odd version)
    // Must use RELAXED load then RELEASE store with barrier
    uint64_t version = __atomic_load_n(&per_ip->version, __ATOMIC_RELAXED);
    __atomic_store_n(&per_ip->version, version + 1, __ATOMIC_RELAXED);
    // Full write barrier AFTER incrementing version to ensure readers see odd version
    // before any data changes become visible
    rte_smp_wmb();

    // Get snapshots for all protected IPs
    struct per_ip_feature_snapshot snapshots[MAX_PROTECTED_IPS_EXPORT];
    uint32_t count = per_ip_features_snapshot_all(snapshots, MAX_PROTECTED_IPS_EXPORT);

    per_ip->active_count = count;

    // Copy snapshots to export structure
    for (uint32_t i = 0; i < count && i < MAX_PROTECTED_IPS_EXPORT; i++) {
        struct l2_per_ip_features_export *out = &per_ip->features[i];
        const struct per_ip_feature_snapshot *in = &snapshots[i];

        out->dst_ip = in->dst_ip;
        out->active = 1;
        out->timestamp_ns = in->timestamp_ns;
        out->window_duration_ns = in->window_duration_ns;

        // Volume
        out->packets_per_sec = in->packets_per_sec;
        out->bytes_per_sec = in->bytes_per_sec;
        out->flows_per_sec = in->flows_per_sec;

        // TCP flags
        out->syn_per_sec = in->syn_per_sec;
        out->syn_ack_per_sec = in->syn_ack_per_sec;
        out->ack_per_sec = in->ack_per_sec;
        out->rst_per_sec = in->rst_per_sec;
        out->fin_per_sec = in->fin_per_sec;

        // Protocol mix
        out->tcp_packets = in->tcp_packets;
        out->udp_packets = in->udp_packets;
        out->icmp_packets = in->icmp_packets;
        out->other_packets = in->other_packets;
        out->tcp_ratio = in->tcp_ratio;
        out->udp_ratio = in->udp_ratio;
        out->icmp_ratio = in->icmp_ratio;

        // Ratios
        out->syn_ack_ratio = in->syn_ack_ratio;
        out->rst_syn_ratio = in->rst_syn_ratio;
        out->bytes_per_packet = in->bytes_per_packet;

        // Cardinality
        out->unique_src_ips = in->unique_src_ips;
        out->unique_src_ports = in->unique_src_ports;
        out->unique_dst_ports = in->unique_dst_ports;
        out->unique_flows = in->unique_flows;

        // Churn
        out->src_ip_churn = in->src_ip_churn;
        out->dst_port_churn = in->dst_port_churn;
        out->expired_srcip_rate = in->expired_srcip_rate;

        // Concentration
        out->max_flow_fraction = in->max_flow_fraction;
        out->topk_flow_share = in->topk_flow_share;
        out->heavy_hitter_count = in->heavy_hitter_count;

        // Flow behavior
        out->avg_packets_per_flow = in->avg_packets_per_flow;
        out->flow_duration_avg_ms = in->flow_duration_avg_ms;

        // TCP flag ratios (as % of TCP packets)
        if (out->tcp_packets > 0) {
            uint32_t tcp = out->tcp_packets;
            out->syn_tcp_ratio    = (uint8_t)((uint64_t)out->syn_per_sec * 100 / (tcp > 0 ? tcp : 1));
            out->synack_tcp_ratio = (uint8_t)((uint64_t)out->syn_ack_per_sec * 100 / (tcp > 0 ? tcp : 1));
            out->ack_tcp_ratio    = (uint8_t)((uint64_t)out->ack_per_sec * 100 / (tcp > 0 ? tcp : 1));
            out->rst_tcp_ratio    = (uint8_t)((uint64_t)out->rst_per_sec * 100 / (tcp > 0 ? tcp : 1));
            out->fin_tcp_ratio    = (uint8_t)((uint64_t)out->fin_per_sec * 100 / (tcp > 0 ? tcp : 1));
        } else {
            out->syn_tcp_ratio = out->synack_tcp_ratio = out->ack_tcp_ratio = 0;
            out->rst_tcp_ratio = out->fin_tcp_ratio = 0;
        }

        // Burst factor: use global burst_factor (per-IP burst would need per-IP EWMA)
        out->burst_factor = 100;  // Default normal, per-IP burst detection is a future enhancement

        // UDP flow ratio and ICMP echo ratio not available per-IP (no per-IP counters yet)
        out->udp_flow_ratio = 0;
        out->icmp_echo_ratio = 0;

        // Dst port density: unique_dst_ports / PPS * 1000
        out->dst_port_density = (out->packets_per_sec > 0) ?
            (uint16_t)((uint64_t)out->unique_dst_ports * 1000 / out->packets_per_sec) : 0;

        // New L2 features (5)
        out->small_pkt_ratio = in->small_pkt_ratio;
        out->tcp_completion_rate = in->tcp_completion_rate;
        out->fragment_ratio = in->fragment_ratio;
        out->src_port_entropy = in->src_port_entropy;
        out->ttl_mean = in->ttl_mean;

        // Metadata
        out->active_flows = in->active_flows;
        out->sample_count = in->sample_count;
        out->total_packets = in->total_packets;
    }

    // Clear remaining slots
    for (uint32_t i = count; i < MAX_PROTECTED_IPS_EXPORT; i++) {
        per_ip->features[i].active = 0;
        per_ip->features[i].dst_ip = 0;
    }

    // Memory barrier before publishing version
    rte_smp_wmb();

    // Seqlock: mark write complete (even version)
    __atomic_store_n(&per_ip->version, version + 2, __ATOMIC_RELEASE);

    // Reset all per-IP windows AFTER export is complete
    // This ensures the next export cycle will have fresh delta values
    per_ip_features_reset_all_windows();
}

struct l2_per_ip_export *l2_per_ip_export_get(void) {
    if (!shared_mem) return NULL;
    return &shared_mem->l2_per_ip;
}

// ==================== Per-IP Anomaly State API ====================

/**
 * Find slot index for a given protected IP
 * Returns -1 if not found
 */
static int per_ip_anomaly_find_slot(uint32_t dst_ip) {
    if (!shared_mem) return -1;

    struct l2_per_ip_export *per_ip = &shared_mem->l2_per_ip;

    for (uint32_t i = 0; i < MAX_PROTECTED_IPS_EXPORT; i++) {
        if (__atomic_load_n(&per_ip->anomaly[i].active, __ATOMIC_ACQUIRE) &&
            per_ip->anomaly[i].dst_ip == dst_ip) {
            return (int)i;
        }
    }
    return -1;
}

/**
 * Find or allocate slot for a given protected IP
 * Uses atomic CAS to prevent race conditions during allocation
 */
int per_ip_anomaly_get_slot(uint32_t dst_ip) {
    if (!shared_mem) return -1;

    struct l2_per_ip_export *per_ip = &shared_mem->l2_per_ip;

    // First, look for existing slot
    int idx = per_ip_anomaly_find_slot(dst_ip);
    if (idx >= 0) return idx;

    // Find first empty slot using atomic CAS to prevent race conditions
    for (uint32_t i = 0; i < MAX_PROTECTED_IPS_EXPORT; i++) {
        uint32_t expected = 0;
        // Atomically try to claim this slot
        if (__atomic_compare_exchange_n(&per_ip->anomaly[i].active,
                                         &expected, 1,
                                         false,  // strong CAS
                                         __ATOMIC_ACQ_REL,
                                         __ATOMIC_ACQUIRE)) {
            // Successfully claimed slot, now set the IP
            __atomic_store_n(&per_ip->anomaly[i].dst_ip, dst_ip, __ATOMIC_RELEASE);
            return (int)i;
        }
        // Slot was already taken, check if it's ours (another thread might have
        // allocated for the same IP between our find_slot and here)
        if (__atomic_load_n(&per_ip->anomaly[i].dst_ip, __ATOMIC_ACQUIRE) == dst_ip) {
            return (int)i;
        }
    }

    return -1;  // No slots available
}

void per_ip_anomaly_set(uint32_t dst_ip, uint32_t level, double z_score,
                        uint32_t tier_agreement, uint32_t feature_count) {
    if (!shared_mem) return;

    // Validate level to prevent out-of-bounds values
    if (level > ANOMALY_LEVEL_CRITICAL) {
        level = ANOMALY_LEVEL_CRITICAL;
    }

    int idx = per_ip_anomaly_get_slot(dst_ip);
    if (idx < 0) {
        RTE_LOG(WARNING, SHMEM, "No slot available for per-IP anomaly state\n");
        return;
    }

    // Verify idx is within bounds (defensive check)
    if (idx >= MAX_PROTECTED_IPS_EXPORT) {
        RTE_LOG(ERR, SHMEM, "Invalid slot index %d for per-IP anomaly\n", idx);
        return;
    }

    struct per_ip_anomaly_state *state = &shared_mem->l2_per_ip.anomaly[idx];
    uint64_t now_ns = get_timestamp_ns();

    // Use atomic operations for fields that may be read concurrently
    uint32_t was_active = __atomic_load_n(&state->anomaly_active, __ATOMIC_ACQUIRE);

    // Set anomaly start time only on first detection
    if (!was_active && level > ANOMALY_LEVEL_NONE) {
        __atomic_store_n(&state->anomaly_start_ns, now_ns, __ATOMIC_RELAXED);
    }

    // Update fields with proper memory ordering:
    // Write data fields first (RELAXED), then set active flag last (RELEASE).
    // Readers load anomaly_active with ACQUIRE, which ensures they see all prior writes.
    __atomic_store_n(&state->anomaly_level, level, __ATOMIC_RELAXED);
    // double isn't guaranteed atomic, but we're single-writer so this is safe
    state->max_z_score = z_score;
    __atomic_store_n(&state->tier_agreement, tier_agreement, __ATOMIC_RELAXED);
    __atomic_store_n(&state->anomalous_feature_count, feature_count, __ATOMIC_RELAXED);
    __atomic_store_n(&state->last_update_ns, now_ns, __ATOMIC_RELAXED);
    // Active flag LAST with RELEASE -- acts as the publish barrier for all fields above
    __atomic_store_n(&state->anomaly_active, (level > ANOMALY_LEVEL_NONE) ? 1 : 0, __ATOMIC_RELEASE);

    if (level > ANOMALY_LEVEL_NONE && !was_active) {
        RTE_LOG(INFO, SHMEM, "Per-IP anomaly set: IP=%08x level=%u z=%.2f\n",
                dst_ip, level, z_score);
    }
}

void per_ip_anomaly_set_ex(uint32_t dst_ip, uint32_t level, double z_score,
                           uint32_t tier_agreement, uint32_t feature_count,
                           uint8_t proto_cat, uint8_t attack_type, uint16_t dst_port) {
    if (!shared_mem) return;

    // Validate level to prevent out-of-bounds values
    if (level > ANOMALY_LEVEL_CRITICAL) {
        level = ANOMALY_LEVEL_CRITICAL;
    }

    int idx = per_ip_anomaly_get_slot(dst_ip);
    if (idx < 0) {
        RTE_LOG(WARNING, SHMEM, "No slot available for per-IP anomaly state\n");
        return;
    }

    // Verify idx is within bounds (defensive check)
    if (idx >= MAX_PROTECTED_IPS_EXPORT) {
        RTE_LOG(ERR, SHMEM, "Invalid slot index %d for per-IP anomaly\n", idx);
        return;
    }

    struct per_ip_anomaly_state *state = &shared_mem->l2_per_ip.anomaly[idx];
    uint64_t now_ns = get_timestamp_ns();

    // Use atomic operations for fields that may be read concurrently
    uint32_t was_active = __atomic_load_n(&state->anomaly_active, __ATOMIC_ACQUIRE);

    // Set anomaly start time only on first detection
    if (!was_active && level > ANOMALY_LEVEL_NONE) {
        __atomic_store_n(&state->anomaly_start_ns, now_ns, __ATOMIC_RELAXED);
    }

    // Update fields with proper memory ordering
    __atomic_store_n(&state->anomaly_active, (level > ANOMALY_LEVEL_NONE) ? 1 : 0, __ATOMIC_RELAXED);
    __atomic_store_n(&state->anomaly_level, level, __ATOMIC_RELAXED);
    // double isn't guaranteed atomic, but we're single-writer so this is safe
    state->max_z_score = z_score;
    __atomic_store_n(&state->tier_agreement, tier_agreement, __ATOMIC_RELAXED);
    __atomic_store_n(&state->anomalous_feature_count, feature_count, __ATOMIC_RELAXED);

    // Protocol-specific fields (NEW)
    __atomic_store_n(&state->anomaly_protocol, proto_cat, __ATOMIC_RELAXED);
    __atomic_store_n(&state->attack_type, attack_type, __ATOMIC_RELAXED);
    __atomic_store_n(&state->anomaly_dst_port, dst_port, __ATOMIC_RELAXED);

    __atomic_store_n(&state->last_update_ns, now_ns, __ATOMIC_RELEASE);

    if (level > ANOMALY_LEVEL_NONE && !was_active) {
        const char *proto_name;
        switch (proto_cat) {
            case PROTO_CAT_TCP:   proto_name = "TCP"; break;
            case PROTO_CAT_UDP:   proto_name = "UDP"; break;
            case PROTO_CAT_ICMP:  proto_name = "ICMP"; break;
            case PROTO_CAT_OTHER: proto_name = "OTHER"; break;
            default:              proto_name = "ALL"; break;
        }
        if (dst_port != 0) {
            RTE_LOG(INFO, SHMEM, "Per-IP anomaly set: IP=%08x level=%u z=%.2f proto=%s port=%u attack=%u\n",
                    dst_ip, level, z_score, proto_name, dst_port, attack_type);
        } else {
            RTE_LOG(INFO, SHMEM, "Per-IP anomaly set: IP=%08x level=%u z=%.2f proto=%s attack=%u\n",
                    dst_ip, level, z_score, proto_name, attack_type);
        }
    }
}

void per_ip_anomaly_set_flash_crowd(uint32_t dst_ip,
                                     double flash_crowd_score,
                                     double syn_completion,
                                     double response_ratio) {
    if (!shared_mem) return;

    int idx = per_ip_anomaly_find_slot(dst_ip);
    if (idx < 0) return;

    struct per_ip_anomaly_state *state = &shared_mem->l2_per_ip.anomaly[idx];

    // Scale 0.0-1.0 floats to 0-100 uint8_t
    uint8_t fc = (uint8_t)(flash_crowd_score * 100.0 + 0.5);
    if (fc > 100) fc = 100;
    uint8_t sc = (uint8_t)(syn_completion * 100.0 + 0.5);
    if (sc > 100) sc = 100;
    uint8_t rr = (uint8_t)(response_ratio * 100.0 + 0.5);
    if (rr > 100) rr = 100;

    __atomic_store_n(&state->flash_crowd_score, fc, __ATOMIC_RELAXED);
    __atomic_store_n(&state->syn_completion_pct, sc, __ATOMIC_RELAXED);
    __atomic_store_n(&state->response_ratio_pct, rr, __ATOMIC_RELAXED);
}

void per_ip_anomaly_clear(uint32_t dst_ip) {
    if (!shared_mem) return;

    int idx = per_ip_anomaly_find_slot(dst_ip);
    if (idx < 0) return;

    // Use atomic stores consistent with per_ip_anomaly_set
    struct per_ip_anomaly_state *state = &shared_mem->l2_per_ip.anomaly[idx];
    __atomic_store_n(&state->anomaly_active, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&state->anomaly_level, ANOMALY_LEVEL_NONE, __ATOMIC_RELAXED);
    double zero = 0.0;
    __atomic_store(&state->max_z_score, &zero, __ATOMIC_RELAXED);
    __atomic_store_n(&state->tier_agreement, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&state->anomalous_feature_count, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&state->anomaly_protocol, PROTO_CAT_ALL, __ATOMIC_RELAXED);
    __atomic_store_n(&state->attack_type, SHM_ATTACK_UNKNOWN, __ATOMIC_RELAXED);
    __atomic_store_n(&state->anomaly_dst_port, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&state->flash_crowd_score, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&state->syn_completion_pct, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&state->response_ratio_pct, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&state->spoofed_mode, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&state->randomness_pct, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&state->rate_limit_pct, 100, __ATOMIC_RELAXED);
    // Clear detection method details
    __atomic_store_n(&state->detection_method, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&state->sensitivity_preset, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&state->learning_phase, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&state->tier1_progress, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&state->cool_down_remaining, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&state->peak_z_feature, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&state->cusum_triggered, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&state->jsd_triggered, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&state->fast_triggered, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&state->confidence, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&state->severity, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&state->last_update_ns, get_timestamp_ns(), __ATOMIC_RELEASE);

    // Release the slot so it can be reused by per_ip_anomaly_get_slot()
    __atomic_store_n(&state->dst_ip, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&state->active, 0, __ATOMIC_RELEASE);

    RTE_LOG(INFO, SHMEM, "Per-IP anomaly cleared and slot released: IP=%08x\n", dst_ip);
}

bool per_ip_anomaly_is_active(uint32_t dst_ip) {
    if (!shared_mem) return false;

    int idx = per_ip_anomaly_find_slot(dst_ip);
    if (idx < 0) return false;

    return __atomic_load_n(&shared_mem->l2_per_ip.anomaly[idx].anomaly_active,
                           __ATOMIC_ACQUIRE) != 0;
}

uint32_t per_ip_anomaly_get_level(uint32_t dst_ip) {
    if (!shared_mem) return ANOMALY_LEVEL_NONE;

    int idx = per_ip_anomaly_find_slot(dst_ip);
    if (idx < 0) return ANOMALY_LEVEL_NONE;

    return __atomic_load_n(&shared_mem->l2_per_ip.anomaly[idx].anomaly_level,
                           __ATOMIC_ACQUIRE);
}

const struct per_ip_anomaly_state *per_ip_anomaly_get_fast(int32_t idx) {
    if (!shared_mem || idx < 0 || idx >= MAX_PROTECTED_IPS_EXPORT) return NULL;
    return &shared_mem->l2_per_ip.anomaly[idx];
}

void per_ip_anomaly_set_spoofed_mode(uint32_t dst_ip, uint8_t spoofed, uint8_t randomness_pct) {
    if (!shared_mem) return;
    int idx = per_ip_anomaly_find_slot(dst_ip);
    if (idx < 0) return;
    struct per_ip_anomaly_state *state = &shared_mem->l2_per_ip.anomaly[idx];
    __atomic_store_n(&state->spoofed_mode, spoofed ? 1 : 0, __ATOMIC_RELAXED);
    __atomic_store_n(&state->randomness_pct, randomness_pct > 100 ? 100 : randomness_pct,
                     __ATOMIC_RELAXED);
}

void per_ip_anomaly_set_rate_limit_pct(uint32_t dst_ip, uint8_t pct) {
    if (!shared_mem) return;
    int idx = per_ip_anomaly_find_slot(dst_ip);
    if (idx < 0) return;
    struct per_ip_anomaly_state *state = &shared_mem->l2_per_ip.anomaly[idx];
    __atomic_store_n(&state->rate_limit_pct, pct, __ATOMIC_RELAXED);
}

void per_ip_anomaly_set_detection_details(uint32_t dst_ip,
    uint8_t detection_method, uint8_t sensitivity_preset,
    uint8_t learning_phase, uint8_t tier1_progress,
    uint16_t cool_down_remaining, uint8_t peak_z_feature,
    uint8_t cusum_triggered, uint8_t jsd_triggered,
    uint8_t fast_triggered, uint8_t confidence, uint8_t severity) {
    if (!shared_mem) return;
    int idx = per_ip_anomaly_find_slot(dst_ip);
    if (idx < 0) return;
    struct per_ip_anomaly_state *state = &shared_mem->l2_per_ip.anomaly[idx];
    state->detection_method = detection_method;
    state->sensitivity_preset = sensitivity_preset;
    state->learning_phase = learning_phase;
    state->tier1_progress = tier1_progress;
    state->cool_down_remaining = cool_down_remaining;
    state->peak_z_feature = peak_z_feature;
    state->cusum_triggered = cusum_triggered;
    state->jsd_triggered = jsd_triggered;
    state->fast_triggered = fast_triggered;
    state->confidence = confidence;
    state->severity = severity;
}

// ==================== Heavy Hitter Export ====================

uint32_t get_per_ip_top_talkers(struct per_ip_stats *stats, uint32_t max_count) {
    if (!stats || max_count == 0 || !shared_mem) {
        return 0;
    }

    uint32_t count = 0;
    struct l2_per_ip_export *per_ip = &shared_mem->l2_per_ip;

    // Collect stats from all active per-IP feature slots
    for (uint32_t i = 0; i < MAX_PROTECTED_IPS_EXPORT && count < max_count; i++) {
        struct l2_per_ip_features_export *feat = &per_ip->features[i];
        struct per_ip_anomaly_state *anom = &per_ip->anomaly[i];

        if (!__atomic_load_n(&feat->active, __ATOMIC_ACQUIRE)) {
            continue;
        }

        // Copy data to output
        stats[count].ip = feat->dst_ip;
        stats[count].total_packets = feat->total_packets;
        stats[count].total_bytes = feat->packets_per_sec * feat->sample_count;  // Estimate
        stats[count].current_pps = feat->packets_per_sec;
        stats[count].current_bps = feat->bytes_per_sec;
        stats[count].first_seen = feat->timestamp_ns / 1000000000ULL - feat->sample_count;
        stats[count].last_seen = feat->timestamp_ns / 1000000000ULL;

        // Get reputation from anomaly state if available
        if (__atomic_load_n(&anom->active, __ATOMIC_ACQUIRE) &&
            anom->dst_ip == feat->dst_ip) {
            stats[count].reputation = (uint16_t)(anom->anomaly_active ? 100 : 500);
            stats[count].blocked = anom->anomaly_active ? 1 : 0;
            stats[count].attack_type = (uint8_t)anom->anomaly_level;
        } else {
            stats[count].reputation = 500;  // Default neutral
            stats[count].blocked = 0;
            stats[count].attack_type = 0;
        }

        count++;
    }

    return count;
}

