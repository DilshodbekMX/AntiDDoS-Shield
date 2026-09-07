#include "latency_histogram.h"
#include <rte_malloc.h>
#include <rte_log.h>
#include <rte_cycles.h>
#include <string.h>
#include <stdio.h>

#define RTE_LOGTYPE_LATHIST RTE_LOGTYPE_USER6

// ==================== State ====================

static bool initialized = false;
static uint64_t tsc_hz = 0;  // TSC frequency for conversions

// Per-lcore histograms for each type
static struct latency_histogram *lcore_hists[LAT_TYPE_MAX] = {NULL};

// ==================== Initialization ====================

int latency_histogram_init(void) {
    if (initialized) {
        return 0;
    }

    tsc_hz = rte_get_tsc_hz();
    if (tsc_hz == 0) {
        RTE_LOG(ERR, LATHIST, "Failed to get TSC frequency\n");
        return -1;
    }

    // Allocate per-lcore histograms for each type
    for (int t = 0; t < LAT_TYPE_MAX; t++) {
        lcore_hists[t] = rte_zmalloc_socket("latency_hist",
                                             sizeof(struct latency_histogram) * RTE_MAX_LCORE,
                                             RTE_CACHE_LINE_SIZE,
                                             SOCKET_ID_ANY);
        if (!lcore_hists[t]) {
            RTE_LOG(ERR, LATHIST, "Failed to allocate histogram type %d\n", t);
            // Cleanup already allocated
            for (int i = 0; i < t; i++) {
                rte_free(lcore_hists[i]);
                lcore_hists[i] = NULL;
            }
            return -1;
        }

        // Initialize min to max value
        for (unsigned int i = 0; i < RTE_MAX_LCORE; i++) {
            lcore_hists[t][i].min_us = UINT64_MAX;
        }
    }

    initialized = true;
    RTE_LOG(INFO, LATHIST, "Latency histogram initialized (TSC freq: %lu Hz)\n", tsc_hz);
    return 0;
}

void latency_histogram_cleanup(void) {
    if (!initialized) return;

    for (int t = 0; t < LAT_TYPE_MAX; t++) {
        if (lcore_hists[t]) {
            rte_free(lcore_hists[t]);
            lcore_hists[t] = NULL;
        }
    }

    initialized = false;
    RTE_LOG(INFO, LATHIST, "Latency histogram cleanup complete\n");
}

// ==================== Recording ====================

void latency_histogram_record(enum latency_type type, uint64_t latency_us) {
    if (!initialized || type >= LAT_TYPE_MAX) {
        return;
    }

    unsigned int lcore_id = rte_lcore_id();
    if (lcore_id >= RTE_MAX_LCORE) lcore_id = 0;

    struct latency_histogram *hist = &lcore_hists[type][lcore_id];

    // Get bucket and increment
    int bucket = latency_get_bucket(latency_us);
    hist->buckets[bucket]++;
    hist->count++;
    hist->sum_us += latency_us;

    // Update min/max
    if (latency_us < hist->min_us) hist->min_us = latency_us;
    if (latency_us > hist->max_us) hist->max_us = latency_us;
}

void latency_histogram_record_tsc(enum latency_type type, uint64_t tsc_delta) {
    if (!initialized || tsc_hz == 0) {
        return;
    }

    // Convert TSC cycles to microseconds
    // Use 64-bit arithmetic to avoid overflow
    uint64_t latency_us = (tsc_delta * 1000000ULL) / tsc_hz;

    latency_histogram_record(type, latency_us);
}

// ==================== Aggregation ====================

void latency_histogram_get(enum latency_type type, struct latency_histogram *out) {
    if (!out || !initialized || type >= LAT_TYPE_MAX) {
        if (out) memset(out, 0, sizeof(*out));
        return;
    }

    memset(out, 0, sizeof(*out));
    out->min_us = UINT64_MAX;

    unsigned int lcore_id;
    RTE_LCORE_FOREACH(lcore_id) {
        struct latency_histogram *src = &lcore_hists[type][lcore_id];

        for (int b = 0; b < LATENCY_HIST_BUCKETS; b++) {
            out->buckets[b] += src->buckets[b];
        }
        out->count += src->count;
        out->sum_us += src->sum_us;

        if (src->min_us < out->min_us && src->count > 0) {
            out->min_us = src->min_us;
        }
        if (src->max_us > out->max_us) {
            out->max_us = src->max_us;
        }
    }

    // If no data, reset min to 0
    if (out->count == 0) {
        out->min_us = 0;
    }
}

uint64_t latency_histogram_percentile(const struct latency_histogram *hist, int percentile) {
    if (!hist || hist->count == 0 || percentile < 0 || percentile > 100) {
        return 0;
    }

    // Calculate target count for percentile
    uint64_t target = (hist->count * percentile) / 100;
    uint64_t cumulative = 0;

    for (int b = 0; b < LATENCY_HIST_BUCKETS; b++) {
        cumulative += hist->buckets[b];
        if (cumulative >= target) {
            // Return upper bound of this bucket as percentile estimate
            if (b == 0) return latency_bucket_boundaries_us[0];
            if (b >= LATENCY_HIST_OVERFLOW) return hist->max_us;
            return latency_bucket_boundaries_us[b];
        }
    }

    return hist->max_us;
}

// ==================== Reset ====================

void latency_histogram_reset(void) {
    if (!initialized) return;

    for (int t = 0; t < LAT_TYPE_MAX; t++) {
        unsigned int lcore_id;
        RTE_LCORE_FOREACH(lcore_id) {
            struct latency_histogram *hist = &lcore_hists[t][lcore_id];
            memset(hist->buckets, 0, sizeof(hist->buckets));
            hist->count = 0;
            hist->sum_us = 0;
            hist->min_us = UINT64_MAX;
            hist->max_us = 0;
        }
    }
}

// ==================== Printing ====================

const char* latency_bucket_label(int bucket) {
    static const char *labels[] = {
        "0-10us",
        "10-50us",
        "50-100us",
        "100-500us",
        "500us-1ms",
        "1-5ms",
        "5-10ms",
        "10-50ms",
        "50-100ms",
        "100-500ms",
        "500ms-1s",
        "1-5s",
        ">5s"
    };

    if (bucket >= 0 && bucket < LATENCY_HIST_BUCKETS) {
        return labels[bucket];
    }
    return "invalid";
}

const char* latency_type_str(enum latency_type type) {
    static const char *names[] = {
        "syn_synack",
        "processing"
    };

    if (type < LAT_TYPE_MAX) {
        return names[type];
    }
    return "unknown";
}

void latency_histogram_print(enum latency_type type) {
    struct latency_histogram hist;
    latency_histogram_get(type, &hist);

    printf("Latency Histogram: %s\n", latency_type_str(type));
    printf("  Count: %lu, Mean: %lu us, Min: %lu us, Max: %lu us\n",
           hist.count, latency_histogram_mean(&hist), hist.min_us, hist.max_us);

    if (hist.count > 0) {
        printf("  P50: %lu us, P90: %lu us, P95: %lu us, P99: %lu us\n",
               latency_histogram_percentile(&hist, 50),
               latency_histogram_percentile(&hist, 90),
               latency_histogram_percentile(&hist, 95),
               latency_histogram_percentile(&hist, 99));

        printf("  Distribution:\n");
        for (int b = 0; b < LATENCY_HIST_BUCKETS; b++) {
            if (hist.buckets[b] > 0) {
                double pct = (double)hist.buckets[b] / hist.count * 100.0;
                printf("    %12s: %8lu (%5.1f%%)\n",
                       latency_bucket_label(b), hist.buckets[b], pct);
            }
        }
    }
}
