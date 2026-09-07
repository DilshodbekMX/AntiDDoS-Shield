#include "heavy_hitter_export.h"
#include "../tables/count_min_sketch.h"
#include "../interlayer/shared_memory.h"
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_lcore.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <arpa/inet.h>

#define RTE_LOGTYPE_HHEXP RTE_LOGTYPE_USER7

// ==================== State ====================

static bool initialized = false;

// ==================== Initialization ====================

int heavy_hitter_export_init(void) {
    if (initialized) {
        return 0;
    }

    initialized = true;
    RTE_LOG(INFO, HHEXP, "Heavy hitter export initialized\n");
    return 0;
}

void heavy_hitter_export_cleanup(void) {
    if (!initialized) return;
    initialized = false;
    RTE_LOG(INFO, HHEXP, "Heavy hitter export cleanup complete\n");
}

// ==================== Sorting ====================

static int compare_by_packets(const void *a, const void *b) {
    const struct heavy_hitter_entry *ea = (const struct heavy_hitter_entry *)a;
    const struct heavy_hitter_entry *eb = (const struct heavy_hitter_entry *)b;
    if (eb->packets > ea->packets) return 1;
    if (eb->packets < ea->packets) return -1;
    return 0;
}

static int compare_by_bytes(const void *a, const void *b) {
    const struct heavy_hitter_entry *ea = (const struct heavy_hitter_entry *)a;
    const struct heavy_hitter_entry *eb = (const struct heavy_hitter_entry *)b;
    if (eb->bytes > ea->bytes) return 1;
    if (eb->bytes < ea->bytes) return -1;
    return 0;
}

static int compare_by_pps(const void *a, const void *b) {
    const struct heavy_hitter_entry *ea = (const struct heavy_hitter_entry *)a;
    const struct heavy_hitter_entry *eb = (const struct heavy_hitter_entry *)b;
    if (eb->pps > ea->pps) return 1;
    if (eb->pps < ea->pps) return -1;
    return 0;
}

static int compare_by_bps(const void *a, const void *b) {
    const struct heavy_hitter_entry *ea = (const struct heavy_hitter_entry *)a;
    const struct heavy_hitter_entry *eb = (const struct heavy_hitter_entry *)b;
    if (eb->bps > ea->bps) return 1;
    if (eb->bps < ea->bps) return -1;
    return 0;
}

// ==================== IP String Conversion ====================

static void ip_to_str(uint32_t ip, char *buf, size_t buf_size) {
    struct in_addr addr;
    addr.s_addr = ip;
    inet_ntop(AF_INET, &addr, buf, buf_size);
}

// ==================== Data Collection ====================

/**
 * Collect heavy hitters from per-IP feature tracking
 * This is a snapshot operation - may briefly see inconsistent data
 */
static uint32_t collect_heavy_hitters(struct heavy_hitter_entry *entries,
                                       uint32_t max_entries) {
    uint32_t count = 0;

    // Get all tracked IPs from per-IP features
    // This uses the shared memory interface
    struct per_ip_stats stats[HH_MAX_TOP_N];
    uint32_t num_ips = get_per_ip_top_talkers(stats, max_entries);

    for (uint32_t i = 0; i < num_ips && count < max_entries; i++) {
        entries[count].ip = stats[i].ip;
        entries[count].packets = stats[i].total_packets;
        entries[count].bytes = stats[i].total_bytes;
        entries[count].pps = stats[i].current_pps;
        entries[count].bps = stats[i].current_bps;
        entries[count].first_seen = stats[i].first_seen;
        entries[count].last_seen = stats[i].last_seen;
        entries[count].reputation = stats[i].reputation;
        entries[count].blocked = stats[i].blocked ? 1 : 0;
        entries[count].attack_type = stats[i].attack_type;
        count++;
    }

    return count;
}

// ==================== Public API ====================

uint32_t heavy_hitter_get_top(struct heavy_hitter_export *result,
                               uint32_t top_n,
                               enum hh_sort_by sort_by) {
    if (!result || !initialized) {
        return 0;
    }

    if (top_n > HH_MAX_TOP_N) {
        top_n = HH_MAX_TOP_N;
    }

    memset(result, 0, sizeof(*result));
    result->timestamp = (uint64_t)time(NULL);

    // Collect data
    struct heavy_hitter_entry all_entries[HH_MAX_TOP_N];
    uint32_t total = collect_heavy_hitters(all_entries, HH_MAX_TOP_N);

    result->total_unique_ips = total;

    if (total == 0) {
        result->count = 0;
        return 0;
    }

    // Sort by requested criteria
    int (*compare_func)(const void *, const void *);
    switch (sort_by) {
        case HH_SORT_BY_BYTES:
            compare_func = compare_by_bytes;
            break;
        case HH_SORT_BY_PPS:
            compare_func = compare_by_pps;
            break;
        case HH_SORT_BY_BPS:
            compare_func = compare_by_bps;
            break;
        case HH_SORT_BY_PACKETS:
        default:
            compare_func = compare_by_packets;
            break;
    }

    qsort(all_entries, total, sizeof(struct heavy_hitter_entry), compare_func);

    // Copy top N to result
    result->count = (top_n < total) ? top_n : total;
    memcpy(result->entries, all_entries, result->count * sizeof(struct heavy_hitter_entry));

    return result->count;
}

// ==================== JSON Export ====================

static int export_json(const struct heavy_hitter_export *data,
                        char *buf, size_t buf_size) {
    int len = 0;
    int ret;

    #define JSON_ADD(fmt, ...) do { \
        ret = snprintf(buf + len, buf_size - len, fmt, ##__VA_ARGS__); \
        if (ret > 0 && len + ret < (int)buf_size) len += ret; \
        else return -1; \
    } while(0)

    JSON_ADD("{\n");
    JSON_ADD("  \"timestamp\": %lu,\n", data->timestamp);
    JSON_ADD("  \"total_unique_ips\": %u,\n", data->total_unique_ips);
    JSON_ADD("  \"count\": %u,\n", data->count);
    JSON_ADD("  \"heavy_hitters\": [\n");

    for (uint32_t i = 0; i < data->count; i++) {
        const struct heavy_hitter_entry *e = &data->entries[i];
        char ip_str[INET_ADDRSTRLEN];
        ip_to_str(e->ip, ip_str, sizeof(ip_str));

        JSON_ADD("    {\n");
        JSON_ADD("      \"ip\": \"%s\",\n", ip_str);
        JSON_ADD("      \"packets\": %lu,\n", e->packets);
        JSON_ADD("      \"bytes\": %lu,\n", e->bytes);
        JSON_ADD("      \"pps\": %lu,\n", e->pps);
        JSON_ADD("      \"bps\": %lu,\n", e->bps);
        JSON_ADD("      \"first_seen\": %lu,\n", e->first_seen);
        JSON_ADD("      \"last_seen\": %lu,\n", e->last_seen);
        JSON_ADD("      \"reputation\": %u,\n", e->reputation);
        JSON_ADD("      \"blocked\": %s,\n", e->blocked ? "true" : "false");
        JSON_ADD("      \"attack_type\": %u\n", e->attack_type);
        JSON_ADD("    }%s\n", (i < data->count - 1) ? "," : "");
    }

    JSON_ADD("  ]\n");
    JSON_ADD("}\n");

    #undef JSON_ADD

    return len;
}

// ==================== CSV Export ====================

static int export_csv(const struct heavy_hitter_export *data,
                       char *buf, size_t buf_size) {
    int len = 0;
    int ret;

    #define CSV_ADD(fmt, ...) do { \
        ret = snprintf(buf + len, buf_size - len, fmt, ##__VA_ARGS__); \
        if (ret > 0 && len + ret < (int)buf_size) len += ret; \
        else return -1; \
    } while(0)

    // Header
    CSV_ADD("timestamp,ip,packets,bytes,pps,bps,first_seen,last_seen,reputation,blocked,attack_type\n");

    for (uint32_t i = 0; i < data->count; i++) {
        const struct heavy_hitter_entry *e = &data->entries[i];
        char ip_str[INET_ADDRSTRLEN];
        ip_to_str(e->ip, ip_str, sizeof(ip_str));

        CSV_ADD("%lu,%s,%lu,%lu,%lu,%lu,%lu,%lu,%u,%u,%u\n",
                data->timestamp,
                ip_str,
                e->packets,
                e->bytes,
                e->pps,
                e->bps,
                e->first_seen,
                e->last_seen,
                e->reputation,
                e->blocked,
                e->attack_type);
    }

    #undef CSV_ADD

    return len;
}

// ==================== Binary Export ====================

static int export_binary(const struct heavy_hitter_export *data,
                          char *buf, size_t buf_size) {
    // Simple binary format:
    // [8 bytes: timestamp]
    // [4 bytes: total_unique_ips]
    // [4 bytes: count]
    // [count * sizeof(heavy_hitter_entry): entries]

    size_t header_size = 8 + 4 + 4;
    size_t entry_size = sizeof(struct heavy_hitter_entry);
    size_t total_size = header_size + (data->count * entry_size);

    if (total_size > buf_size) {
        return -1;
    }

    // Write header
    memcpy(buf, &data->timestamp, 8);
    memcpy(buf + 8, &data->total_unique_ips, 4);
    memcpy(buf + 12, &data->count, 4);

    // Write entries
    if (data->count > 0) {
        memcpy(buf + header_size, data->entries, data->count * entry_size);
    }

    return (int)total_size;
}

// ==================== Buffer Export ====================

int heavy_hitter_export_to_buffer(uint32_t top_n,
                                   enum hh_sort_by sort_by,
                                   enum hh_export_format format,
                                   char *buf,
                                   size_t buf_size) {
    if (!buf || buf_size == 0 || !initialized) {
        return -1;
    }

    struct heavy_hitter_export data;
    heavy_hitter_get_top(&data, top_n, sort_by);

    switch (format) {
        case HH_FORMAT_JSON:
            return export_json(&data, buf, buf_size);
        case HH_FORMAT_CSV:
            return export_csv(&data, buf, buf_size);
        case HH_FORMAT_BINARY:
            return export_binary(&data, buf, buf_size);
        default:
            return -1;
    }
}

// ==================== File Export ====================

int heavy_hitter_export_to_file(uint32_t top_n,
                                 enum hh_sort_by sort_by,
                                 enum hh_export_format format,
                                 const char *filepath) {
    if (!filepath || !initialized) {
        return -1;
    }

    // Allocate buffer
    size_t buf_size = 64 * 1024;  // 64 KB should be enough
    char *buf = malloc(buf_size);
    if (!buf) {
        RTE_LOG(ERR, HHEXP, "Failed to allocate export buffer\n");
        return -1;
    }

    int len = heavy_hitter_export_to_buffer(top_n, sort_by, format, buf, buf_size);
    if (len < 0) {
        free(buf);
        return -1;
    }

    // Write to file
    FILE *fp = fopen(filepath, "wb");
    if (!fp) {
        RTE_LOG(ERR, HHEXP, "Failed to open file '%s' for writing\n", filepath);
        free(buf);
        return -1;
    }

    size_t written = fwrite(buf, 1, len, fp);
    fclose(fp);
    free(buf);

    if (written != (size_t)len) {
        RTE_LOG(ERR, HHEXP, "Failed to write all data to file\n");
        return -1;
    }

    RTE_LOG(INFO, HHEXP, "Exported %u heavy hitters to '%s'\n", top_n, filepath);
    return 0;
}

// ==================== Utility ====================

const char* heavy_hitter_sort_str(enum hh_sort_by sort) {
    static const char *names[] = {
        "packets",
        "bytes",
        "pps",
        "bps"
    };
    if (sort < HH_SORT_MAX) {
        return names[sort];
    }
    return "unknown";
}

const char* heavy_hitter_format_str(enum hh_export_format format) {
    static const char *names[] = {
        "json",
        "csv",
        "binary"
    };
    if (format < HH_FORMAT_MAX) {
        return names[format];
    }
    return "unknown";
}
