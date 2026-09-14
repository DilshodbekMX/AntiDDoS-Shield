#ifndef LAYER2_BASELINES_H
#define LAYER2_BASELINES_H

#include <stdint.h>
#include <stdbool.h>
#include <math.h>
#include <time.h>

/**
 * @file baselines.h
 * @brief Three-Tier EWMA Baseline System for Anomaly Detection
 *
 * Implements a three-tier Exponentially Weighted Moving Average (EWMA) baseline
 * system for statistical anomaly detection:
 *
 * Tier 1 (Immediate): Fast adaptation (alpha=0.2), ready in ~10 seconds
 *                     Detects sudden spikes immediately
 *
 * Tier 2 (Hourly):    Medium adaptation (alpha=0.1), 24 hourly baselines
 *                     Captures time-of-day patterns (e.g., lunch rush)
 *
 * Tier 3 (Weekly):    Slow adaptation (alpha=0.05), 168 baselines (7x24)
 *                     Captures day-of-week patterns (e.g., Monday morning)
 *
 * EWMA Formula:
 *   mean_new = mean_old + alpha * (value - mean_old)
 *   variance_new = (1 - alpha) * (variance_old + alpha * delta^2)
 *
 * Z-Score Formula:
 *   z = (observed - mean) / stddev
 */

// ==================== Feature Definitions ====================

/**
 * Features tracked by Layer 2 for anomaly detection (39 features total)
 *
 * Categories:
 * - Volume (4): packets/sec, bytes/sec, flows/sec, burst_factor
 * - TCP Flags (5): SYN, SYN-ACK, ACK, RST, FIN rates
 * - TCP Flag Ratios (5): SYN/TCP, SYNACK/TCP, ACK/TCP, RST/TCP, FIN/TCP %
 * - Protocol Mix (5): TCP/UDP/ICMP/OTHER ratios, icmp_echo_ratio
 * - Ratios (4): SYN/ACK, RST/SYN, bytes/packet, tcp_completion_rate
 * - Cardinality (4): Unique src IPs, dst ports, flows, dst_port_density
 * - Churn (1): Source IP churn rate
 * - Concentration (3): Top flow %, heavy hitters, top-K flow share
 * - Flow Behavior (3): packets/flow, flow duration avg, udp_flow_ratio
 * - Entropy (2): src_ip_entropy, src_port_entropy
 * - Packet Characteristics (3): small_pkt_ratio, fragment_ratio, ttl_mean
 */
enum l2_feature_index {
    // ===== VOLUME FEATURES (3) =====
    L2_FEAT_PACKETS_PER_SEC = 0,    // Total packets/second
    L2_FEAT_BYTES_PER_SEC,          // Total bytes/second
    L2_FEAT_FLOWS_PER_SEC,          // New flows/second

    // ===== TCP FLAG FEATURES (5) =====
    L2_FEAT_SYN_PER_SEC,            // SYN packets/second
    L2_FEAT_SYN_ACK_PER_SEC,        // SYN-ACK packets/second
    L2_FEAT_ACK_PER_SEC,            // ACK packets/second
    L2_FEAT_RST_PER_SEC,            // RST packets/second
    L2_FEAT_FIN_PER_SEC,            // FIN packets/second

    // ===== PROTOCOL MIX FEATURES (4) =====
    L2_FEAT_TCP_RATIO,              // TCP % (0-100)
    L2_FEAT_UDP_RATIO,              // UDP % (0-100)
    L2_FEAT_ICMP_RATIO,             // ICMP % (0-100)
    L2_FEAT_OTHER_RATIO,            // Other protocols % (0-100)

    // ===== RATIO FEATURES (3) =====
    L2_FEAT_SYN_ACK_RATIO,          // SYN/ACK ratio * 100
    L2_FEAT_RST_SYN_RATIO,          // RST/SYN ratio * 100
    L2_FEAT_BYTES_PER_PACKET,       // Average bytes per packet

    // ===== CARDINALITY FEATURES (3) =====
    L2_FEAT_UNIQUE_SRC_IPS,         // Unique source IPs (HyperLogLog)
    L2_FEAT_UNIQUE_DST_PORTS,       // Unique destination ports (HyperLogLog)
    L2_FEAT_UNIQUE_FLOWS,           // Unique flows (HyperLogLog)

    // ===== CHURN FEATURES (1) =====
    L2_FEAT_NEW_SRCIP_RATE,         // New source IP churn rate

    // ===== CONCENTRATION FEATURES (3) =====
    L2_FEAT_MAX_FLOW_FRACTION,      // Top flow as % of total (0-100)
    L2_FEAT_TOPK_FLOW_SHARE,        // Top-10 flows as % of total (0-100)
    L2_FEAT_HEAVY_HITTER_COUNT,     // Heavy hitters detected (Count-Min Sketch)

    // ===== FLOW BEHAVIOR FEATURES (2) =====
    L2_FEAT_AVG_PACKETS_PER_FLOW,   // Average packets per flow
    L2_FEAT_FLOW_DURATION_AVG,      // Average flow duration in ms

    // ===== TCP FLAG RATIO FEATURES (5) =====
    L2_FEAT_SYN_TCP_RATIO,          // SYN as % of TCP packets (0-100)
    L2_FEAT_SYNACK_TCP_RATIO,       // SYN-ACK as % of TCP packets (0-100)
    L2_FEAT_ACK_TCP_RATIO,          // ACK as % of TCP packets (0-100)
    L2_FEAT_RST_TCP_RATIO,          // RST as % of TCP packets (0-100)
    L2_FEAT_FIN_TCP_RATIO,          // FIN as % of TCP packets (0-100)

    // ===== VOLUME EXTENDED (1) =====
    L2_FEAT_BURST_FACTOR,           // Current PPS / EWMA PPS * 100 (100=normal)

    // ===== FLOW BEHAVIOR EXTENDED (1) =====
    L2_FEAT_UDP_FLOW_RATIO,         // UDP flows / UDP PPS * 100

    // ===== PROTOCOL MIX EXTENDED (1) =====
    L2_FEAT_ICMP_ECHO_RATIO,        // ICMP echo / ICMP total * 100

    // ===== CARDINALITY EXTENDED (1) =====
    L2_FEAT_DST_PORT_DENSITY,       // Unique dst ports / PPS * 1000

    // ===== ENTROPY FEATURES (2) =====
    L2_FEAT_SRC_IP_ENTROPY,         // Source IP distribution entropy (0-8 bits)
    L2_FEAT_SRC_PORT_ENTROPY,       // Source port distribution entropy (0-8 bits)

    // ===== PACKET CHARACTERISTICS (3) =====
    L2_FEAT_SMALL_PKT_RATIO,        // Packets <= 64B as % of total
    L2_FEAT_FRAGMENT_RATIO,         // Fragment packets as % of total
    L2_FEAT_TTL_MEAN,               // Mean IP TTL value

    // ===== RATIO EXTENDED (1) =====
    L2_FEAT_TCP_COMPLETION_RATE,    // SYN-ACK / SYN * 100

    L2_MAX_FEATURES                 // Total: 39 features
};

/**
 * Feature names for logging
 */
extern const char *l2_feature_names[L2_MAX_FEATURES];

// ==================== Baseline Structures ====================

/**
 * Single feature EWMA baseline
 * Tracks mean, variance, and statistics for one feature
 */
struct feature_baseline {
    double mean;                    // EWMA mean
    double variance;                // EWMA variance (for stddev calculation)
    double min_observed;            // Minimum value ever observed
    double max_observed;            // Maximum value ever observed
    uint32_t sample_count;          // Number of samples processed
    uint64_t last_update_ns;        // Timestamp of last update (nanoseconds)
} __attribute__((aligned(64)));

/**
 * Tier baseline - collection of feature baselines
 * Represents one tier (immediate, hourly, or weekly)
 */
struct tier_baseline {
    char name[32];                  // Tier name for logging
    double alpha;                   // EWMA smoothing factor
    bool frozen;                    // True if frozen (during attack)
    bool ready;                     // True if has enough samples
    uint32_t min_samples_ready;     // Minimum samples before ready
    struct feature_baseline features[L2_MAX_FEATURES];
} __attribute__((aligned(64)));

/**
 * Baseline poisoning detection state
 * Tracks rapid baseline changes that could indicate slow-rate attack adaptation
 */
struct baseline_poison_tracker {
    uint64_t window_start_ns;               // Start of tracking window
    uint32_t large_change_count;            // Count of large changes in window
    double last_mean[L2_MAX_FEATURES];      // Previous mean values for comparison
    bool poison_detected;                   // True if poisoning was detected
    uint64_t poison_detected_ns;            // When poisoning was detected
};

/**
 * Complete three-tier baseline system
 */
struct three_tier_baseline {
    struct tier_baseline immediate;         // Tier 1: alpha=0.2, global
    struct tier_baseline hourly[24];        // Tier 2: alpha=0.1, per hour (0-23)
    struct tier_baseline weekly[168];       // Tier 3: alpha=0.05, per day*24+hour

    // Single global frozen flag for O(1) atomic freeze/unfreeze
    // Old code looped through 193 tiers (1+24+168) for each freeze/unfreeze
    // Now: one atomic write instead of 193.
    // Access via __atomic builtins only -- not C11 _Atomic to stay memset-safe.
    bool globally_frozen;

    // Baseline poisoning protection
    struct baseline_poison_tracker poison_tracker;

    // Metadata
    uint64_t creation_time_ns;
    uint64_t last_save_time_ns;
    uint32_t total_updates;
};

/**
 * Feature snapshot - current values for all features
 */
struct l2_feature_snapshot {
    double values[L2_MAX_FEATURES];
    uint64_t timestamp_ns;
};

/**
 * Z-score results for all features in a tier
 */
struct tier_z_scores {
    double z[L2_MAX_FEATURES];
    double max_z;
    int max_feature_idx;
    int triggered_count;            // Features exceeding threshold
};

/**
 * Baseline summary for status reporting
 */
struct baseline_summary {
    // Tier 1 status
    bool tier1_ready;
    uint32_t tier1_samples;
    double tier1_pps_mean;
    double tier1_pps_stddev;

    // Tier 2 status
    uint32_t tier2_ready_count;     // How many of 24 are ready
    int current_hour;

    // Tier 3 status
    uint32_t tier3_ready_count;     // How many of 168 are ready
    int current_day;

    // Global
    bool any_frozen;
    uint32_t total_updates;
};

// ==================== Per-IP Baseline Structures ====================

/**
 * Maximum number of protected IPs for baseline tracking
 * Should match MAX_PROTECTED_IPS_EXPORT from shared_memory.h
 */
#define L2_MAX_PROTECTED_IPS 64

/**
 * Per-IP baseline system
 * Each protected IP gets its own three-tier baseline system PLUS its own
 * CUSUM and JSD detectors (). Pre-fix the
 * per-IP detection loop in layer2.c::layer2_per_ip_detection_cycle
 * called only l2_detect_anomaly (z-tier voting) and did not exercise
 * the CUSUM + JSD ensemble that the global detection_cycle_advanced
 * path runs. Adding per-IP CUSUM + JSD here lets l2_advanced_detect
 * run on each protected IP with that IP's own baseline state.
 *
 * Forward-declared types -- `struct cusum_detector` and `struct
 * jsd_baseline` are defined in advanced_detection.h, and `struct
 * innovation_gate` in innovation_gate.h, none of which baselines.h
 * includes (to avoid cyclic inclusion). Callers that touch
 * per_ip_baseline.cusum / .jsd / .innovation include those headers.
 */
struct cusum_detector;
struct jsd_baseline;
struct innovation_gate;

struct per_ip_baseline {
    uint32_t dst_ip;                        // Protected IP (network byte order)
    bool active;                            // True if slot is in use
    struct three_tier_baseline baselines;   // Full three-tier baselines for this IP
    /* Pointers to per-IP CUSUM and JSD state, lazily allocated when the IP is
     * registered. NULL until per_ip_baseline_register() allocates them. */
    struct cusum_detector *cusum;
    struct jsd_baseline *jsd;
    /* Per-IP innovation-gate (the innovation-gate prototype) state -- one surprise latch PER protected IP.
     * Lazily allocated by layer2_per_ip_detection_cycle() only when the
     * innovation-gate ensemble rule is selected (off by default), so unused
     * slots cost only a NULL pointer. Freed in per_ip_baseline_unregister(). */
    struct innovation_gate *innovation;
};

/**
 * Per-IP anomaly state for detection results
 */
struct per_ip_anomaly_result {
    uint32_t dst_ip;                        // Protected IP (network byte order)
    bool active;                            // True if slot is in use
    bool anomaly_detected;                  // True if anomaly detected this cycle
    uint32_t anomaly_level;                 // L2_ANOMALY_* level
    double max_z_score;                     // Highest z-score across all tiers
    uint32_t tier_agreement;                // Number of tiers agreeing on anomaly
    uint32_t anomalous_feature_count;       // Number of features flagged
    int anomalous_features[L2_MAX_FEATURES]; // Feature indices that triggered
    uint64_t anomaly_start_ns;              // When anomaly started
    uint64_t last_update_ns;                // Last detection timestamp
};

/**
 * Collection of per-IP baselines
 */
struct per_ip_baseline_table {
    struct per_ip_baseline entries[L2_MAX_PROTECTED_IPS];
    struct per_ip_anomaly_result anomaly[L2_MAX_PROTECTED_IPS];
    uint32_t active_count;
    bool globally_frozen;                    // Freeze all per-IP baselines (use __atomic builtins)
};

// ==================== Initialization ====================

/**
 * Initialize a feature baseline
 */
void feature_baseline_init(struct feature_baseline *fb);

/**
 * Initialize a tier baseline with name and alpha
 */
void tier_baseline_init(struct tier_baseline *tier, const char *name,
                        double alpha, uint32_t min_samples);

/**
 * Initialize complete three-tier baseline system
 */
void three_tier_baseline_init(struct three_tier_baseline *baselines,
                              double alpha_immediate,
                              double alpha_hourly,
                              double alpha_weekly,
                              uint32_t min_samples_immediate,
                              uint32_t min_samples_hourly,
                              uint32_t min_samples_weekly);

// ==================== EWMA Update ====================

/**
 * Update a single feature baseline with new value
 * Uses EWMA formula: mean = mean + alpha * (value - mean)
 *
 * @param fb Feature baseline to update
 * @param value New observed value
 * @param alpha EWMA smoothing factor (0 < alpha <= 1)
 * @param timestamp_ns Current timestamp in nanoseconds
 */
void feature_baseline_update(struct feature_baseline *fb,
                             double value,
                             double alpha,
                             uint64_t timestamp_ns);

/**
 * Update all features in a tier baseline
 *
 * @param tier Tier baseline to update
 * @param snapshot Current feature values
 */
void tier_baseline_update(struct tier_baseline *tier,
                          const struct l2_feature_snapshot *snapshot);

/**
 * Update all three tiers with new feature values
 * Automatically selects correct hourly/weekly baseline based on current time
 *
 * @param baselines Three-tier baseline system
 * @param snapshot Current feature values
 */
void three_tier_baseline_update(struct three_tier_baseline *baselines,
                                const struct l2_feature_snapshot *snapshot);

// ==================== Z-Score Calculation ====================

/**
 * Calculate Z-score for a single feature
 *
 * @param fb Feature baseline
 * @param value Current observed value
 * @return Z-score (0.0 if not ready or zero variance)
 */
double feature_baseline_z_score(const struct feature_baseline *fb, double value);

/**
 * Calculate Z-scores for all features in a tier
 *
 * @param tier Tier baseline
 * @param snapshot Current feature values
 * @param threshold Z-score threshold for triggered count
 * @param result Output: Z-scores and statistics
 */
void tier_baseline_z_scores(const struct tier_baseline *tier,
                            const struct l2_feature_snapshot *snapshot,
                            double threshold,
                            struct tier_z_scores *result);

// ==================== Tier Selection ====================

/**
 * Get current hourly baseline (based on current hour 0-23)
 */
struct tier_baseline *get_current_hourly_baseline(struct three_tier_baseline *baselines);

/**
 * Get current weekly baseline (based on current day and hour)
 */
struct tier_baseline *get_current_weekly_baseline(struct three_tier_baseline *baselines);

/**
 * Get hourly baseline index (0-23) for current time
 */
int get_current_hour_index(void);

/**
 * Offline-replay seam: force the tier-2/3 slot indices instead of reading the wall clock.
 *
 * Online, wall-clock time is the data's time and no override is needed. Replaying a
 * historical capture must select the slot from each window's own timestamp, or every
 * window lands in the slot the replay happens to execute in. Pass hour 0-23 and weekly
 * 0-167 (Monday = 0); any out-of-range value clears that override. The live path is
 * unchanged while no override is set.
 */
void l2_set_replay_slot(int hour_index, int weekly_index);

/** Clear both replay overrides and return to wall-clock slot selection. */
void l2_clear_replay_slot(void);

/**
 * Get weekly baseline index (0-167) for current time
 */
int get_current_weekly_index(void);

// ==================== Freeze Control ====================

/**
 * Freeze all baselines (during attack)
 * Prevents attack traffic from polluting learned baselines
 */
void three_tier_baseline_freeze(struct three_tier_baseline *baselines);

/**
 * Unfreeze all baselines (attack ended)
 */
void three_tier_baseline_unfreeze(struct three_tier_baseline *baselines);

/**
 * Check if any baseline is frozen
 */
bool three_tier_baseline_is_frozen(const struct three_tier_baseline *baselines);

// ==================== Baseline Poisoning Protection ====================

/**
 * Check for baseline poisoning (slow-rate attack adaptation)
 *
 * Detects when baselines are changing too rapidly, which could indicate
 * an attacker slowly ramping up traffic to avoid detection.
 *
 * @param baselines Three-tier baseline system with poison tracker
 * @param snapshot Current feature values (pre-update)
 * @return true if poisoning detected, baseline should be frozen
 */
bool baseline_check_poisoning(struct three_tier_baseline *baselines,
                              const struct l2_feature_snapshot *snapshot);

/**
 * Reset poisoning detection state
 * Call after attack ends or false positive confirmed
 */
void baseline_poison_tracker_reset(struct three_tier_baseline *baselines);

/**
 * Check if baseline is currently in poisoned state
 */
bool baseline_is_poisoned(const struct three_tier_baseline *baselines);

// ==================== Status ====================

/**
 * Check if a tier is ready (has enough samples)
 */
bool tier_baseline_is_ready(const struct tier_baseline *tier);

/**
 * Get summary of baseline status
 */
void three_tier_baseline_summary(const struct three_tier_baseline *baselines,
                                 struct baseline_summary *summary);

/**
 * Reset all baselines to initial state
 */
void three_tier_baseline_reset(struct three_tier_baseline *baselines);

// ==================== Persistence ====================

/**
 * MF5 FIX: Baseline schema version for compatibility
 *
 * Version history:
 *   1 - Initial version (24 features)
 *   2 - Added feature_count field for forward compatibility
 *
 * Migration rules:
 *   - v1 -> v2: Add feature_count, fill missing features with zeros
 *   - Newer -> Older: Silently drop extra features
 */
#define L2_BASELINE_SCHEMA_VERSION 2
#define L2_BASELINE_MIN_COMPATIBLE_VERSION 1

/**
 * Serialize baselines to JSON string
 * Includes schema version for compatibility
 * Caller must free the returned string
 */
char *three_tier_baseline_to_json(const struct three_tier_baseline *baselines);

/**
 * Deserialize baselines from JSON string
 * Handles version migration automatically
 * @return 0 on success, -1 on error, -2 on incompatible version
 */
int three_tier_baseline_from_json(struct three_tier_baseline *baselines,
                                  const char *json);

/**
 * MF5 FIX: Get schema version from JSON without full parse
 * @return Version number, or -1 on error
 */
int three_tier_baseline_get_json_version(const char *json);

/**
 * Save baselines to file (synchronous)
 */
int three_tier_baseline_save(const struct three_tier_baseline *baselines,
                             const char *filepath);

/**
 * P1 FIX: Save baselines to file asynchronously
 * Serializes JSON in calling thread, writes to disk in background thread.
 * Use this from detection thread to avoid I/O latency spikes.
 */
int three_tier_baseline_save_async(const struct three_tier_baseline *baselines,
                                   const char *filepath);

/**
 * Load baselines from file
 */
int three_tier_baseline_load(struct three_tier_baseline *baselines,
                             const char *filepath);

// ==================== Inline Helpers ====================

/**
 * P2 FIX: Centralized time utility (was duplicated in 3 files)
 * Get current time in nanoseconds using CLOCK_MONOTONIC
 */
static inline uint64_t get_current_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/**
 * Calculate standard deviation from variance
 */
static inline double feature_baseline_stddev(const struct feature_baseline *fb) {
    return (fb->variance > 0.0) ? sqrt(fb->variance) : 0.0;
}

/**
 * Check if feature baseline has enough samples
 */
static inline bool feature_baseline_is_ready(const struct feature_baseline *fb,
                                             uint32_t min_samples) {
    return fb->sample_count >= min_samples;
}

// ==================== Per-IP Baseline API ====================

/**
 * Initialize per-IP baseline table
 */
void per_ip_baseline_table_init(struct per_ip_baseline_table *table);

/**
 * Register a protected IP for baseline tracking
 * @param table Per-IP baseline table
 * @param dst_ip Protected IP (network byte order)
 * @param alpha_* EWMA parameters from config
 * @param min_samples_* Minimum samples parameters from config
 * @return 0 on success, -1 if table full
 */
int per_ip_baseline_register(struct per_ip_baseline_table *table,
                             uint32_t dst_ip,
                             double alpha_immediate,
                             double alpha_hourly,
                             double alpha_weekly,
                             uint32_t min_samples_immediate,
                             uint32_t min_samples_hourly,
                             uint32_t min_samples_weekly);

/**
 * Unregister a protected IP from baseline tracking
 * @param table Per-IP baseline table
 * @param dst_ip Protected IP (network byte order)
 * @return 0 on success, -1 if not found
 */
int per_ip_baseline_unregister(struct per_ip_baseline_table *table,
                               uint32_t dst_ip);

/**
 * Get baseline for a specific protected IP
 * @param table Per-IP baseline table
 * @param dst_ip Protected IP (network byte order)
 * @return Pointer to per_ip_baseline or NULL if not found
 */
struct per_ip_baseline *per_ip_baseline_lookup(struct per_ip_baseline_table *table,
                                               uint32_t dst_ip);

/**
 * Get anomaly result for a specific protected IP
 * @param table Per-IP baseline table
 * @param dst_ip Protected IP (network byte order)
 * @return Pointer to per_ip_anomaly_result or NULL if not found
 */
struct per_ip_anomaly_result *per_ip_anomaly_lookup(struct per_ip_baseline_table *table,
                                                    uint32_t dst_ip);

/**
 * Update baselines for a protected IP with new feature values
 * @param table Per-IP baseline table
 * @param dst_ip Protected IP (network byte order)
 * @param snapshot Current feature values
 */
void per_ip_baseline_update(struct per_ip_baseline_table *table,
                            uint32_t dst_ip,
                            const struct l2_feature_snapshot *snapshot);

/**
 * Freeze all per-IP baselines (during attack)
 */
void per_ip_baseline_freeze_all(struct per_ip_baseline_table *table);

/**
 * Unfreeze all per-IP baselines (attack ended)
 */
void per_ip_baseline_unfreeze_all(struct per_ip_baseline_table *table);

/**
 * Check if per-IP baselines are frozen
 */
bool per_ip_baseline_is_frozen(const struct per_ip_baseline_table *table);

/**
 * Reset all per-IP baselines
 */
void per_ip_baseline_table_reset(struct per_ip_baseline_table *table);

/**
 * Get count of active per-IP baselines
 */
uint32_t per_ip_baseline_count(const struct per_ip_baseline_table *table);

/**
 * Save per-IP baselines to file
 */
int per_ip_baseline_save(const struct per_ip_baseline_table *table,
                         const char *filepath);

/**
 * Load per-IP baselines from file
 */
int per_ip_baseline_load(struct per_ip_baseline_table *table,
                         const char *filepath);

#endif // LAYER2_BASELINES_H
