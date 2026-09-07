#include "realtime_telemetry.h"
#include <rte_log.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <time.h>

#define RTE_LOGTYPE_RTTEL RTE_LOGTYPE_USER4

// ==================== Global State ====================

static void *shm_base = NULL;
static size_t shm_size = 0;
static int shm_fd = -1;
static bool initialized = false;

// Pointers into shared memory (set during init)
static struct rt_shm_header *shm_header = NULL;
static struct rt_global_stats *global_stats = NULL;
static struct rt_lcore_stats *lcore_stats = NULL;
static struct rt_ring_header *event_ring_hdr = NULL;
static struct rt_event *event_ring_data = NULL;
static struct rt_ring_header *flow_ring_hdr = NULL;
static struct rt_flow_summary *flow_ring_data = NULL;

// ==================== Initialization ====================

int realtime_telemetry_init(void) {
    if (initialized) {
        RTE_LOG(WARNING, RTTEL, "Already initialized\n");
        return 0;
    }

    // Calculate total size
    size_t header_size = sizeof(struct rt_shm_header);
    size_t global_size = sizeof(struct rt_global_stats);
    size_t lcore_size = sizeof(struct rt_lcore_stats) * RT_MAX_LCORES;
    size_t event_ring_hdr_size = sizeof(struct rt_ring_header);
    size_t event_ring_data_size = sizeof(struct rt_event) * EVENT_RING_SIZE;
    size_t flow_ring_hdr_size = sizeof(struct rt_ring_header);
    size_t flow_ring_data_size = sizeof(struct rt_flow_summary) * FLOW_RING_SIZE;

    shm_size = header_size + global_size + lcore_size +
               event_ring_hdr_size + event_ring_data_size +
               flow_ring_hdr_size + flow_ring_data_size;

    // Round up to page size
    long page_size = sysconf(_SC_PAGESIZE);
    shm_size = ((shm_size + page_size - 1) / page_size) * page_size;

    RTE_LOG(INFO, RTTEL, "Creating shared memory: %zu bytes\n", shm_size);

    // Create shared memory file
    shm_fd = open(REALTIME_SHM_PATH, O_CREAT | O_RDWR | O_TRUNC, 0644);
    if (shm_fd < 0) {
        RTE_LOG(ERR, RTTEL, "Failed to create %s: %s\n",
                REALTIME_SHM_PATH, strerror(errno));
        return -1;
    }

    // Set size
    if (ftruncate(shm_fd, shm_size) < 0) {
        RTE_LOG(ERR, RTTEL, "Failed to set shm size: %s\n", strerror(errno));
        close(shm_fd);
        unlink(REALTIME_SHM_PATH);
        return -1;
    }

    // Map into memory
    shm_base = mmap(NULL, shm_size, PROT_READ | PROT_WRITE,
                    MAP_SHARED, shm_fd, 0);
    if (shm_base == MAP_FAILED) {
        RTE_LOG(ERR, RTTEL, "Failed to mmap: %s\n", strerror(errno));
        close(shm_fd);
        unlink(REALTIME_SHM_PATH);
        return -1;
    }

    // Zero initialize
    memset(shm_base, 0, shm_size);

    // Set up pointers
    uint8_t *ptr = (uint8_t *)shm_base;

    shm_header = (struct rt_shm_header *)ptr;
    ptr += header_size;

    global_stats = (struct rt_global_stats *)ptr;
    ptr += global_size;

    lcore_stats = (struct rt_lcore_stats *)ptr;
    ptr += lcore_size;

    event_ring_hdr = (struct rt_ring_header *)ptr;
    ptr += event_ring_hdr_size;

    event_ring_data = (struct rt_event *)ptr;
    ptr += event_ring_data_size;

    flow_ring_hdr = (struct rt_ring_header *)ptr;
    ptr += flow_ring_hdr_size;

    flow_ring_data = (struct rt_flow_summary *)ptr;

    // Initialize header
    shm_header->magic = REALTIME_SHM_MAGIC;
    shm_header->version = REALTIME_SHM_VERSION;
    shm_header->num_lcores = rte_lcore_count();
    shm_header->creation_time = time(NULL);
    shm_header->total_size = shm_size;

    // Calculate offsets
    shm_header->global_stats_offset = (uint8_t *)global_stats - (uint8_t *)shm_base;
    shm_header->lcore_stats_offset = (uint8_t *)lcore_stats - (uint8_t *)shm_base;
    shm_header->event_ring_offset = (uint8_t *)event_ring_hdr - (uint8_t *)shm_base;
    shm_header->flow_ring_offset = (uint8_t *)flow_ring_hdr - (uint8_t *)shm_base;

    // Initialize ring headers
    event_ring_hdr->size = EVENT_RING_SIZE;
    event_ring_hdr->mask = EVENT_RING_SIZE - 1;
    event_ring_hdr->element_size = sizeof(struct rt_event);
    event_ring_hdr->write_idx = 0;

    flow_ring_hdr->size = FLOW_RING_SIZE;
    flow_ring_hdr->mask = FLOW_RING_SIZE - 1;
    flow_ring_hdr->element_size = sizeof(struct rt_flow_summary);
    flow_ring_hdr->write_idx = 0;

    // Initialize global stats with TSC frequency
    global_stats->tsc_hz = rte_get_tsc_hz();

    // Memory barrier to ensure all writes are visible
    __atomic_thread_fence(__ATOMIC_RELEASE);

    initialized = true;

    RTE_LOG(INFO, RTTEL, "Real-time telemetry initialized:\n");
    RTE_LOG(INFO, RTTEL, "  Path: %s\n", REALTIME_SHM_PATH);
    RTE_LOG(INFO, RTTEL, "  Size: %zu bytes\n", shm_size);
    RTE_LOG(INFO, RTTEL, "  Event ring: %d entries\n", EVENT_RING_SIZE);
    RTE_LOG(INFO, RTTEL, "  Flow ring: %d entries\n", FLOW_RING_SIZE);
    RTE_LOG(INFO, RTTEL, "  Lcores: %u\n", shm_header->num_lcores);

    return 0;
}

void realtime_telemetry_cleanup(void) {
    if (!initialized) {
        return;
    }

    RTE_LOG(INFO, RTTEL, "Cleaning up real-time telemetry\n");

    if (shm_base && shm_base != MAP_FAILED) {
        munmap(shm_base, shm_size);
        shm_base = NULL;
    }

    if (shm_fd >= 0) {
        close(shm_fd);
        shm_fd = -1;
    }

    // Optionally remove the file (comment out to persist for debugging)
    // unlink(REALTIME_SHM_PATH);

    shm_header = NULL;
    global_stats = NULL;
    lcore_stats = NULL;
    event_ring_hdr = NULL;
    event_ring_data = NULL;
    flow_ring_hdr = NULL;
    flow_ring_data = NULL;

    initialized = false;
    RTE_LOG(INFO, RTTEL, "Real-time telemetry cleanup complete\n");
}

// ==================== Update Functions ====================

void realtime_telemetry_update_global(const struct rt_global_stats *stats) {
    if (!initialized || !global_stats) {
        return;
    }

    // Copy stats atomically (64-bit writes are atomic on x86-64)
    // Using memcpy for bulk copy, then update timestamp
    memcpy(global_stats, stats, sizeof(*stats));

    // Update timestamp and sequence
    global_stats->last_update_tsc = rte_rdtsc();
    __atomic_add_fetch(&shm_header->update_sequence, 1, __ATOMIC_RELEASE);
}

void realtime_telemetry_update_lcore(unsigned int lcore_id,
                                      const struct rt_lcore_stats *stats) {
    if (!initialized || !lcore_stats) {
        return;
    }

    if (lcore_id >= RT_MAX_LCORES) {
        return;
    }

    // Direct copy to per-lcore slot (no contention)
    memcpy(&lcore_stats[lcore_id], stats, sizeof(*stats));
}

// ==================== Ring Buffer Operations ====================

void realtime_telemetry_record_event(const struct rt_event *event) {
    if (!initialized || !event_ring_hdr || !event_ring_data) {
        return;
    }

    // Get next write index atomically
    uint64_t idx = __atomic_fetch_add(&event_ring_hdr->write_idx, 1, __ATOMIC_RELAXED);
    uint64_t slot = idx & event_ring_hdr->mask;

    // Copy event to ring (overwrites old data if ring is full - that's OK)
    memcpy(&event_ring_data[slot], event, sizeof(*event));

    // Memory barrier to ensure write is visible
    __atomic_thread_fence(__ATOMIC_RELEASE);
}

void realtime_telemetry_record_flow(const struct rt_flow_summary *flow) {
    if (!initialized || !flow_ring_hdr || !flow_ring_data) {
        return;
    }

    // Get next write index atomically
    uint64_t idx = __atomic_fetch_add(&flow_ring_hdr->write_idx, 1, __ATOMIC_RELAXED);
    uint64_t slot = idx & flow_ring_hdr->mask;

    // Copy flow to ring
    memcpy(&flow_ring_data[slot], flow, sizeof(*flow));

    // Memory barrier
    __atomic_thread_fence(__ATOMIC_RELEASE);
}

// ==================== Accessor Functions ====================

void *realtime_telemetry_get_shm(void) {
    return initialized ? shm_base : NULL;
}

size_t realtime_telemetry_get_shm_size(void) {
    return shm_size;
}
