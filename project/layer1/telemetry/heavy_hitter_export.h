#ifndef HEAVY_HITTER_EXPORT_H
#define HEAVY_HITTER_EXPORT_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/**
 * @file heavy_hitter_export.h
 * @brief Heavy Hitter Export
 *
 * Exports top-N IPs by packet/byte count for external analysis.
 * Useful for:
 * - Identifying attack sources
 * - Capacity planning
 * - Forensic analysis
 * - Integration with external SIEM systems
 *
 * Export formats:
 * - JSON for API consumption
 * - CSV for log analysis
 * - Binary for efficient processing
 */

// ==================== Configuration ====================

#define HH_MAX_TOP_N        100     // Maximum exportable top IPs
#define HH_DEFAULT_TOP_N    10      // Default number of top IPs to export

// ==================== Heavy Hitter Entry ====================

/**
 * Heavy hitter entry for a single IP
 */
struct heavy_hitter_entry {
    uint32_t ip;               // IP address (network byte order)
    uint64_t packets;          // Total packets from this IP
    uint64_t bytes;            // Total bytes from this IP
    uint64_t pps;              // Current packets per second
    uint64_t bps;              // Current bytes per second
    uint64_t first_seen;       // First seen timestamp (unix)
    uint64_t last_seen;        // Last seen timestamp (unix)
    uint16_t reputation;       // Current reputation score
    uint8_t  blocked;          // 1 if currently blocked
    uint8_t  attack_type;      // Detected attack type (if any)
    uint32_t _pad;
};

/**
 * Export result container
 */
struct heavy_hitter_export {
    uint64_t timestamp;                           // Export timestamp
    uint32_t count;                               // Number of entries
    uint32_t total_unique_ips;                    // Total unique IPs tracked
    struct heavy_hitter_entry entries[HH_MAX_TOP_N];
};

// ==================== Export Formats ====================

enum hh_export_format {
    HH_FORMAT_JSON = 0,
    HH_FORMAT_CSV,
    HH_FORMAT_BINARY,
    HH_FORMAT_MAX
};

// ==================== Sort Options ====================

enum hh_sort_by {
    HH_SORT_BY_PACKETS = 0,    // Sort by total packets
    HH_SORT_BY_BYTES,          // Sort by total bytes
    HH_SORT_BY_PPS,            // Sort by packets per second
    HH_SORT_BY_BPS,            // Sort by bytes per second
    HH_SORT_MAX
};

// ==================== Public API ====================

/**
 * Initialize heavy hitter export subsystem
 *
 * @return 0 on success, -1 on error
 */
int heavy_hitter_export_init(void);

/**
 * Cleanup heavy hitter export subsystem
 */
void heavy_hitter_export_cleanup(void);

/**
 * Get top heavy hitters
 *
 * @param result     Output structure for results
 * @param top_n      Number of top entries to return (max HH_MAX_TOP_N)
 * @param sort_by    Sorting criteria
 * @return Number of entries returned
 */
uint32_t heavy_hitter_get_top(struct heavy_hitter_export *result,
                               uint32_t top_n,
                               enum hh_sort_by sort_by);

/**
 * Export heavy hitters to buffer in specified format
 *
 * @param top_n      Number of top entries to export
 * @param sort_by    Sorting criteria
 * @param format     Export format
 * @param buf        Output buffer
 * @param buf_size   Buffer size
 * @return Number of bytes written, or -1 on error
 */
int heavy_hitter_export_to_buffer(uint32_t top_n,
                                   enum hh_sort_by sort_by,
                                   enum hh_export_format format,
                                   char *buf,
                                   size_t buf_size);

/**
 * Export heavy hitters to file
 *
 * @param top_n      Number of top entries to export
 * @param sort_by    Sorting criteria
 * @param format     Export format
 * @param filepath   Output file path
 * @return 0 on success, -1 on error
 */
int heavy_hitter_export_to_file(uint32_t top_n,
                                 enum hh_sort_by sort_by,
                                 enum hh_export_format format,
                                 const char *filepath);

/**
 * Get sort criteria name
 */
const char* heavy_hitter_sort_str(enum hh_sort_by sort);

/**
 * Get format name
 */
const char* heavy_hitter_format_str(enum hh_export_format format);

#endif // HEAVY_HITTER_EXPORT_H
