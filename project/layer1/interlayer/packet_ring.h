/**
 * @file packet_ring.h
 * @brief Packet Ring Buffer for Layer 3 Attack Signature Extraction
 *
 * This ring buffer allows Layer 1 to sample packets for Layer 3 to analyze.
 * During anomaly/attack detection, packet sampling rate increases to capture
 * representative attack traffic for signature generation.
 *
 * Thread Safety:
 * - WRITER (Layer 1 data plane): Lock-free single-producer writes
 * - READER (Layer 3 Python): Lock-free single-consumer reads
 * - Uses atomic head/tail pointers with memory barriers
 */

#ifndef PACKET_RING_H
#define PACKET_RING_H

#include <stdint.h>
#include <stdbool.h>

// ==================== Constants ====================

// Ring buffer size (power of 2 for efficient modulo)
#define PACKET_RING_SIZE 65536  // 64K packet samples

// Sampling rates (1:N packets sampled)
#define SAMPLING_RATE_NORMAL   100   // 1:100 during normal operation
#define SAMPLING_RATE_ANOMALY   10   // 1:10 during anomaly detection
#define SAMPLING_RATE_ATTACK     1   // 1:1 (all packets) during confirmed attack

// Maximum payload sample size
#define PAYLOAD_SAMPLE_SIZE 30

// ==================== Packet Sample Structure ====================

/**
 * Sampled packet features for Layer 3 signature extraction
 *
 * Contains all fields needed to generate dynamic signatures:
 * - IP/port/protocol identifying info
 * - TCP-specific fields for SYN flood signatures
 * - Payload sample for pattern matching
 *
 * Size: 64 bytes (cache-line aligned)
 */
struct packet_sample {
    // Timestamp
    uint64_t timestamp_ns;           // Nanoseconds since epoch

    // IP header fields
    uint32_t src_ip;                 // Source IP (network byte order)
    uint32_t dst_ip;                 // Destination IP (protected IP)
    uint16_t src_port;               // Source port
    uint16_t dst_port;               // Destination port
    uint16_t pkt_size;               // Total packet size
    uint8_t  protocol;               // IP protocol (6=TCP, 17=UDP, 1=ICMP)
    uint8_t  ttl;                    // IP TTL

    // TCP-specific fields (only valid if protocol == 6)
    uint8_t  tcp_flags;              // TCP flags (SYN, ACK, FIN, RST, etc.)
    uint8_t  tcp_wscale;             // TCP window scale option (0xFF if not present)
    uint16_t tcp_mss;                // TCP MSS option (0 if not present)
    uint16_t tcp_window;             // TCP window size

    // IP fragment info
    uint16_t ip_frag_offset;         // Fragment offset (0 if not fragmented)
    uint8_t  ip_more_frags;          // More fragments flag

    // Payload info
    uint8_t  payload_len;            // Actual payload length (capped at PAYLOAD_SAMPLE_SIZE)
    uint8_t  payload_sample[PAYLOAD_SAMPLE_SIZE];  // First N bytes of payload

} __attribute__((packed, aligned(64)));

// Verify size
_Static_assert(sizeof(struct packet_sample) == 64,
               "packet_sample must be 64 bytes");

// ==================== Packet Ring Buffer ====================

/**
 * Lock-free SPSC (Single Producer, Single Consumer) ring buffer
 *
 * - Layer 1 writes (producer): increments write_idx after writing
 * - Layer 3 reads (consumer): increments read_idx after reading
 * - Overflow: oldest packets are overwritten (tail drops)
 */
struct packet_ring {
    // Ring buffer entries
    struct packet_sample packets[PACKET_RING_SIZE];

    // Producer state (Layer 1)
    uint64_t write_idx;              // Next index to write (masked for ring)
    uint64_t packets_written;        // Total packets written (monotonic)
    uint64_t packets_dropped;        // Packets dropped due to full buffer

    // Consumer state (Layer 3)
    uint64_t read_idx;               // Next index to read (masked for ring)
    uint64_t packets_read;           // Total packets read

    // Sampling control
    uint32_t sampling_rate;          // Current 1:N sampling rate
    uint32_t sample_counter;         // Counter for sampling (private to writer)

    // Configuration
    uint32_t enabled;                // 0 = disabled, 1 = enabled
    uint32_t target_dst_ip;          // Filter for specific protected IP (0 = all)

    // Protocol filter (NEW) - set by Layer 3 based on Layer 2 anomaly detection
    uint8_t  target_protocol;        // Filter: 6=TCP, 17=UDP, 1=ICMP, 0=all
    uint8_t  target_proto_cat;       // PROTO_CAT_* from shared_memory.h
    uint16_t target_dst_port;        // Filter for specific port (0 = all ports)

    // Version for change detection
    uint64_t version;

    // Padding for cache alignment
    uint8_t _pad[16];                // Reduced to fit new fields
} __attribute__((aligned(64)));

// ==================== Public API ====================

/**
 * Initialize packet ring buffer
 * @return 0 on success, -1 on failure
 */
int packet_ring_init(void);

/**
 * Cleanup packet ring buffer
 */
void packet_ring_cleanup(void);

/**
 * Get pointer to packet ring (for direct access from packet pipeline)
 */
struct packet_ring *packet_ring_get(void);

/**
 * Enable/disable packet sampling
 */
void packet_ring_enable(bool enable);

/**
 * Set sampling rate
 * @param rate  1:N sampling rate (e.g., 100 = sample 1 in 100 packets)
 */
void packet_ring_set_sampling_rate(uint32_t rate);

/**
 * Set target destination IP filter
 * @param dst_ip  Protected IP to sample (0 = sample all)
 */
void packet_ring_set_target(uint32_t dst_ip);

/**
 * Set target protocol filter
 * @param protocol  IP protocol number: 6=TCP, 17=UDP, 1=ICMP, 0=all
 * @param dst_port  Specific destination port to filter (0 = all ports)
 */
void packet_ring_set_protocol_filter(uint8_t protocol, uint16_t dst_port);

/**
 * Fast inline function to write a packet sample (called from data plane)
 *
 * Filters packets by:
 * 1. Destination IP (protected IP under attack)
 * 2. Protocol (TCP/UDP/ICMP based on Layer 2 anomaly detection)
 * 3. Destination port (optional, for targeted attacks)
 *
 * @param pkt  Pointer to packet sample to write
 * @return true if packet was written, false if sampling skipped or filtered
 */
static inline bool packet_ring_write(struct packet_ring *ring,
                                      const struct packet_sample *pkt) {
    if (!ring || !ring->enabled) return false;

    // Sampling: only write every Nth packet
    uint32_t counter = __atomic_fetch_add(&ring->sample_counter, 1, __ATOMIC_RELAXED);
    if (counter % ring->sampling_rate != 0) {
        return false;
    }

    // Filter by destination IP if set (protected IP under attack)
    if (ring->target_dst_ip != 0 && pkt->dst_ip != ring->target_dst_ip) {
        return false;
    }

    // Filter by protocol if set (only sample packets of the anomalous protocol)
    if (ring->target_protocol != 0 && pkt->protocol != ring->target_protocol) {
        return false;
    }

    // Filter by destination port if set (for port-specific attacks)
    if (ring->target_dst_port != 0 && pkt->dst_port != ring->target_dst_port) {
        return false;
    }

    // Get write index
    uint64_t idx = __atomic_load_n(&ring->write_idx, __ATOMIC_RELAXED);
    uint64_t ring_idx = idx & (PACKET_RING_SIZE - 1);

    // Write packet (no locking - SPSC)
    ring->packets[ring_idx] = *pkt;

    // Memory barrier to ensure packet data is visible before updating index
    __atomic_thread_fence(__ATOMIC_RELEASE);

    // Update write index
    __atomic_store_n(&ring->write_idx, idx + 1, __ATOMIC_RELEASE);
    __atomic_fetch_add(&ring->packets_written, 1, __ATOMIC_RELAXED);

    return true;
}

/**
 * Read available packets from ring buffer (called by Layer 3)
 *
 * @param ring      Packet ring to read from
 * @param out       Output array for packets
 * @param max_count Maximum packets to read
 * @return Number of packets read
 */
uint32_t packet_ring_read(struct packet_ring *ring,
                          struct packet_sample *out,
                          uint32_t max_count);

/**
 * Get ring buffer statistics
 */
void packet_ring_get_stats(uint64_t *written, uint64_t *read,
                           uint64_t *dropped, uint32_t *available);

/**
 * Print ring buffer status
 */
void packet_ring_print_stats(void);

#endif // PACKET_RING_H
