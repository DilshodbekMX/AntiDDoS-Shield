/**
 * @file packet_ring.c
 * @brief Packet Ring Buffer Implementation
 */

#include "packet_ring.h"
#include <rte_malloc.h>
#include <rte_log.h>
#include <rte_lcore.h>
#include <string.h>

#define RTE_LOGTYPE_PKTRING RTE_LOGTYPE_USER8

// ==================== Global State ====================

static struct packet_ring *ring = NULL;
static bool initialized = false;

// ==================== Initialization ====================

int packet_ring_init(void) {
    if (initialized) {
        RTE_LOG(WARNING, PKTRING, "Packet ring already initialized\n");
        return 0;
    }

    // Allocate ring buffer (huge pages for performance)
    ring = rte_zmalloc("packet_ring",
                       sizeof(struct packet_ring),
                       RTE_CACHE_LINE_SIZE);
    if (ring == NULL) {
        RTE_LOG(ERR, PKTRING, "Failed to allocate packet ring buffer\n");
        return -1;
    }

    // Initialize state
    ring->write_idx = 0;
    ring->read_idx = 0;
    ring->packets_written = 0;
    ring->packets_read = 0;
    ring->packets_dropped = 0;
    ring->sample_counter = 0;
    ring->sampling_rate = SAMPLING_RATE_NORMAL;
    ring->enabled = 0;  // Start disabled
    ring->target_dst_ip = 0;
    ring->target_protocol = 0;      // Sample all protocols by default
    ring->target_proto_cat = 255;   // PROTO_CAT_ALL
    ring->target_dst_port = 0;      // Sample all ports by default
    ring->version = 0;

    initialized = true;

    RTE_LOG(INFO, PKTRING, "Packet ring initialized:\n");
    RTE_LOG(INFO, PKTRING, "  Ring size: %d packets (%lu MB)\n",
            PACKET_RING_SIZE,
            (PACKET_RING_SIZE * sizeof(struct packet_sample)) / (1024 * 1024));
    RTE_LOG(INFO, PKTRING, "  Initial sampling rate: 1:%d\n", SAMPLING_RATE_NORMAL);

    return 0;
}

void packet_ring_cleanup(void) {
    if (!initialized) return;

    if (ring) {
        rte_free(ring);
        ring = NULL;
    }

    initialized = false;
    RTE_LOG(INFO, PKTRING, "Packet ring cleanup complete\n");
}

struct packet_ring *packet_ring_get(void) {
    return ring;
}

// ==================== Control API ====================

void packet_ring_enable(bool enable) {
    if (!ring) return;

    uint32_t prev = __atomic_exchange_n(&ring->enabled, enable ? 1 : 0,
                                         __ATOMIC_RELEASE);

    if (prev != (enable ? 1 : 0)) {
        RTE_LOG(INFO, PKTRING, "Packet ring %s\n",
                enable ? "enabled" : "disabled");

        // Reset counters when enabling
        if (enable) {
            __atomic_store_n(&ring->sample_counter, 0, __ATOMIC_RELAXED);
            ring->version++;
        }
    }
}

void packet_ring_set_sampling_rate(uint32_t rate) {
    if (!ring) return;
    if (rate == 0) rate = 1;  // Minimum rate is 1:1

    uint32_t old_rate = __atomic_exchange_n(&ring->sampling_rate, rate,
                                             __ATOMIC_RELEASE);

    if (old_rate != rate) {
        RTE_LOG(INFO, PKTRING, "Sampling rate changed: 1:%u -> 1:%u\n",
                old_rate, rate);
        ring->version++;
    }
}

void packet_ring_set_target(uint32_t dst_ip) {
    if (!ring) return;

    __atomic_store_n(&ring->target_dst_ip, dst_ip, __ATOMIC_RELEASE);

    if (dst_ip != 0) {
        RTE_LOG(INFO, PKTRING, "Target filter set: %u.%u.%u.%u\n",
                (dst_ip >> 24) & 0xFF,
                (dst_ip >> 16) & 0xFF,
                (dst_ip >> 8) & 0xFF,
                dst_ip & 0xFF);
    } else {
        RTE_LOG(INFO, PKTRING, "Target filter cleared (sampling all IPs)\n");
    }
    ring->version++;
}

void packet_ring_set_protocol_filter(uint8_t protocol, uint16_t dst_port) {
    if (!ring) return;

    __atomic_store_n(&ring->target_protocol, protocol, __ATOMIC_RELEASE);
    __atomic_store_n(&ring->target_dst_port, dst_port, __ATOMIC_RELEASE);

    const char *proto_name;
    switch (protocol) {
        case 6:  proto_name = "TCP"; break;
        case 17: proto_name = "UDP"; break;
        case 1:  proto_name = "ICMP"; break;
        case 0:  proto_name = "ALL"; break;
        default: proto_name = "OTHER"; break;
    }

    if (protocol != 0 || dst_port != 0) {
        if (dst_port != 0) {
            RTE_LOG(INFO, PKTRING, "Protocol filter set: %s port %u\n",
                    proto_name, dst_port);
        } else {
            RTE_LOG(INFO, PKTRING, "Protocol filter set: %s (all ports)\n",
                    proto_name);
        }
    } else {
        RTE_LOG(INFO, PKTRING, "Protocol filter cleared (sampling all protocols)\n");
    }
    ring->version++;
}

// ==================== Read API ====================

uint32_t packet_ring_read(struct packet_ring *r,
                          struct packet_sample *out,
                          uint32_t max_count) {
    if (!r || !out || max_count == 0) return 0;

    uint32_t count = 0;
    uint64_t read_idx = __atomic_load_n(&r->read_idx, __ATOMIC_ACQUIRE);
    uint64_t write_idx = __atomic_load_n(&r->write_idx, __ATOMIC_ACQUIRE);

    // Calculate available packets
    uint64_t available = write_idx - read_idx;

    // Check for overflow (writer wrapped around reader)
    if (available > PACKET_RING_SIZE) {
        // Reader is too slow - skip to recent packets
        uint64_t dropped = available - PACKET_RING_SIZE;
        read_idx = write_idx - PACKET_RING_SIZE;
        __atomic_fetch_add(&r->packets_dropped, dropped, __ATOMIC_RELAXED);
        available = PACKET_RING_SIZE;
    }

    // Read packets
    while (count < max_count && read_idx < write_idx) {
        uint64_t ring_idx = read_idx & (PACKET_RING_SIZE - 1);

        // Memory barrier to ensure we see the written data
        __atomic_thread_fence(__ATOMIC_ACQUIRE);

        out[count] = r->packets[ring_idx];
        count++;
        read_idx++;
    }

    // Update read index
    __atomic_store_n(&r->read_idx, read_idx, __ATOMIC_RELEASE);
    __atomic_fetch_add(&r->packets_read, count, __ATOMIC_RELAXED);

    return count;
}

// ==================== Statistics ====================

void packet_ring_get_stats(uint64_t *written, uint64_t *read,
                           uint64_t *dropped, uint32_t *available) {
    if (!ring) {
        if (written) *written = 0;
        if (read) *read = 0;
        if (dropped) *dropped = 0;
        if (available) *available = 0;
        return;
    }

    uint64_t w = __atomic_load_n(&ring->packets_written, __ATOMIC_RELAXED);
    uint64_t r = __atomic_load_n(&ring->packets_read, __ATOMIC_RELAXED);
    uint64_t d = __atomic_load_n(&ring->packets_dropped, __ATOMIC_RELAXED);

    if (written) *written = w;
    if (read) *read = r;
    if (dropped) *dropped = d;
    if (available) {
        uint64_t write_idx = __atomic_load_n(&ring->write_idx, __ATOMIC_RELAXED);
        uint64_t read_idx = __atomic_load_n(&ring->read_idx, __ATOMIC_RELAXED);
        uint64_t avail = write_idx - read_idx;
        *available = (avail > PACKET_RING_SIZE) ? PACKET_RING_SIZE : (uint32_t)avail;
    }
}

void packet_ring_print_stats(void) {
    if (!ring) {
        printf("Packet ring not initialized\n");
        return;
    }

    uint64_t written, read, dropped;
    uint32_t available;
    packet_ring_get_stats(&written, &read, &dropped, &available);

    printf("\nPacket Ring Buffer:\n");
    printf("  Status: %s\n", ring->enabled ? "ENABLED" : "DISABLED");
    printf("  Sampling rate: 1:%u\n", ring->sampling_rate);
    printf("  Ring size: %d packets\n", PACKET_RING_SIZE);
    printf("  Available: %u packets\n", available);
    printf("  Written: %lu packets\n", written);
    printf("  Read: %lu packets\n", read);
    printf("  Dropped: %lu packets\n", dropped);

    if (ring->target_dst_ip != 0) {
        uint32_t ip = ring->target_dst_ip;
        printf("  Target IP filter: %u.%u.%u.%u\n",
               (ip >> 24) & 0xFF,
               (ip >> 16) & 0xFF,
               (ip >> 8) & 0xFF,
               ip & 0xFF);
    } else {
        printf("  Target IP filter: all IPs\n");
    }

    // Show protocol filter
    const char *proto_name;
    switch (ring->target_protocol) {
        case 6:  proto_name = "TCP"; break;
        case 17: proto_name = "UDP"; break;
        case 1:  proto_name = "ICMP"; break;
        case 0:  proto_name = "ALL"; break;
        default: proto_name = "OTHER"; break;
    }
    if (ring->target_dst_port != 0) {
        printf("  Protocol filter: %s port %u\n", proto_name, ring->target_dst_port);
    } else {
        printf("  Protocol filter: %s\n", proto_name);
    }
}
