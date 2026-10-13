#ifndef TCP_FINGERPRINT_H
#define TCP_FINGERPRINT_H

#include <stdint.h>
#include <stdbool.h>
#include "../../common/types.h"

/**
 * @file tcp_fingerprint.h
 * @brief TCP Fingerprinting for Bot Detection
 *
 * Passive TCP fingerprinting using SYN packet characteristics to:
 * 1. Detect known attack tools (e.g., hping, nmap, masscan)
 * 2. Identify traffic anomalies (unusual OS distributions)
 * 3. Build baseline of normal client fingerprints
 *
 * Fingerprint components:
 * - Initial TTL (heuristic from received TTL)
 * - TCP Window size
 * - MSS value
 * - Window scale option
 * - SACK permitted option
 * - Timestamp option presence
 * - TCP options order
 *
 * This uses a simplified p0f-like approach optimized for high-speed
 * detection rather than full OS identification.
 */

// ==================== Fingerprint Structures ====================

/**
 * Compact TCP fingerprint (32 bits for hash table efficiency)
 * Stores the key characteristics that differentiate TCP stacks
 */
struct tcp_fingerprint {
    uint8_t  initial_ttl;      // Estimated initial TTL (32, 64, 128, 255)
    uint8_t  window_scale;     // Window scale option value (0-14, 255=not present)
    uint16_t mss;              // MSS value (or 0 if not present)
    uint16_t window_size;      // Initial window size (truncated to 16 bits)
    uint8_t  options_sig;      // Signature of options present (bit flags)
    uint8_t  quirks;           // TCP quirks/anomalies detected
} __attribute__((packed));

// Options signature bits
#define FP_OPT_MSS          0x01
#define FP_OPT_WSCALE       0x02
#define FP_OPT_SACK_PERM    0x04
#define FP_OPT_TIMESTAMP    0x08
#define FP_OPT_NOP          0x10
#define FP_OPT_EOL          0x20

// Quirks flags (unusual behavior)
#define FP_QUIRK_ZERO_ID    0x01  // IP ID = 0
#define FP_QUIRK_DF         0x02  // Don't Fragment set
#define FP_QUIRK_NZ_ID_DF   0x04  // Non-zero ID with DF (unusual)
#define FP_QUIRK_ZERO_STAMP 0x08  // TCP timestamp = 0
#define FP_QUIRK_NZ_ACK     0x10  // Non-zero ACK in SYN
#define FP_QUIRK_NZ_URG     0x20  // URG flag with zero urgent pointer
#define FP_QUIRK_ECNCE      0x40  // ECN CE set

// ==================== Known Fingerprint Categories ====================

enum fp_category {
    FP_CAT_UNKNOWN = 0,
    FP_CAT_WINDOWS,        // Windows OS family
    FP_CAT_LINUX,          // Linux kernel
    FP_CAT_MACOS,          // macOS / iOS
    FP_CAT_ANDROID,        // Android (Linux variant)
    FP_CAT_FREEBSD,        // FreeBSD
    FP_CAT_ATTACK_TOOL,    // Known attack tool signature
    FP_CAT_BOT,            // Known botnet signature
    FP_CAT_SCANNER,        // Port scanner (nmap, masscan)
    FP_CAT_ANOMALOUS,      // Anomalous/invalid combination
    FP_CAT_MAX
};

// ==================== Public API ====================

/**
 * Initialize TCP fingerprinting subsystem
 *
 * @param max_fingerprints  Maximum unique fingerprints to track
 * @return 0 on success, -1 on error
 */
int tcp_fingerprint_init(uint32_t max_fingerprints);

/**
 * Cleanup fingerprinting subsystem
 */
void tcp_fingerprint_cleanup(void);

/**
 * Extract fingerprint from a SYN packet
 *
 * @param features  Packet features (must be TCP SYN)
 * @param fp        Output fingerprint structure
 * @return 0 on success, -1 if not a SYN packet
 */
int tcp_fingerprint_extract(const struct packet_features *features,
                            struct tcp_fingerprint *fp);

/**
 * Classify a fingerprint into a category
 *
 * @param fp  Fingerprint to classify
 * @return Category of the fingerprint
 */
enum fp_category tcp_fingerprint_classify(const struct tcp_fingerprint *fp);

/**
 * Check if fingerprint matches known attack tool
 *
 * @param fp  Fingerprint to check
 * @return true if matches attack tool signature
 */
bool tcp_fingerprint_is_attack_tool(const struct tcp_fingerprint *fp);

/**
 * Check if fingerprint is anomalous (likely spoofed/malformed)
 *
 * @param fp  Fingerprint to check
 * @return true if anomalous
 */
bool tcp_fingerprint_is_anomalous(const struct tcp_fingerprint *fp);

/**
 * Record a fingerprint for baseline tracking
 * Updates internal statistics about fingerprint distribution
 *
 * @param fp  Fingerprint to record
 */
void tcp_fingerprint_record(const struct tcp_fingerprint *fp);

/**
 * Get fingerprint distribution statistics
 *
 * @param category_counts  Output array[FP_CAT_MAX] of counts per category
 * @param total_count      Output: total fingerprints recorded
 */
void tcp_fingerprint_get_stats(uint64_t *category_counts, uint64_t *total_count);

/**
 * Check if current fingerprint distribution is anomalous
 * (e.g., sudden spike in attack tool signatures)
 *
 * @return true if distribution is anomalous
 */
bool tcp_fingerprint_distribution_anomalous(void);

/**
 * Get human-readable category name
 */
const char* tcp_fingerprint_category_str(enum fp_category cat);

/**
 * Hash a fingerprint for use in hash tables
 */
static inline uint32_t tcp_fingerprint_hash(const struct tcp_fingerprint *fp) {
    // Simple hash combining the key fields
    uint32_t h = fp->initial_ttl;
    h = (h << 8) | fp->window_scale;
    h ^= (uint32_t)fp->mss << 16;
    h ^= (uint32_t)fp->window_size;
    h ^= (uint32_t)fp->options_sig << 24;
    return h;
}

/**
 * Compare two fingerprints for equality
 */
static inline bool tcp_fingerprint_equal(const struct tcp_fingerprint *a,
                                         const struct tcp_fingerprint *b) {
    return a->initial_ttl == b->initial_ttl &&
           a->window_scale == b->window_scale &&
           a->mss == b->mss &&
           a->window_size == b->window_size &&
           a->options_sig == b->options_sig;
}

#endif // TCP_FINGERPRINT_H
