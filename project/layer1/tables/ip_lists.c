#include "ip_lists.h"
#include "../telemetry/per_ip_features.h"
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_lpm.h>
#include <rte_log.h>
#include <rte_flow.h>
#include <rte_ethdev.h>
#include <rte_atomic.h>   // rte_smp_wmb
#include <rte_spinlock.h>
#include <rte_malloc.h>
#include <rte_cycles.h>
#include <rte_random.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>

#define RTE_LOGTYPE_IPLIST RTE_LOGTYPE_USER5

// ==================== Global State ====================

// Every writer of the three hashes and the two LPM tables below takes this
// lock. The hashes are created with RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY and
// without MULTI_WRITER_ADD: lookups may run on every lcore while one thread
// writes, but two writers at once can take the same free key slot (rte_hash
// takes it with a single-consumer ring dequeue after releasing its own writer
// lock), which loses a key and leaves a ghost bucket entry. rte_lpm_add() and
// rte_lpm_delete(), the protected-subnet side table and the per-IP feature
// registration have no writer locking of their own. The writers are the
// control socket thread, ip_lists_load() at init and tests; the packet path
// only reads these tables (the legitimate-source table, which packet lcores
// write, is separate and lock-free, see "Legitimate Sources").
static rte_spinlock_t lists_write_lock = RTE_SPINLOCK_INITIALIZER;

// Test seam (see ip_lists.h): this weak default does nothing
__attribute__((weak)) void ip_lists_write_seam(void) {
}

static inline void lists_write_begin(void) {
    rte_spinlock_lock(&lists_write_lock);
}

// The writer's table change is done: the seam runs while the lock is held
static inline void lists_write_end(void) {
    ip_lists_write_seam();
    rte_spinlock_unlock(&lists_write_lock);
}

bool ip_lists_writer_lock_held(void) {
    return rte_spinlock_is_locked(&lists_write_lock) != 0;
}

static struct rte_hash *whitelist_hash = NULL;
static struct rte_hash *blacklist_hash = NULL;
static struct rte_hash *protected_hash = NULL;
static struct rte_lpm *whitelist_lpm = NULL;
static struct rte_lpm *protected_lpm = NULL;   // CIDR protected subnets (LPM)
static struct ip_lists_config config;

// Protected-subnet side table. The LPM next_hop encodes (index + 1) into this
// array (0 = miss), so a lookup recovers which subnet matched and its network
// address (needed to key per-IP feature aggregation by subnet).
#define MAX_PROTECTED_SUBNETS 256
static struct protected_subnet_entry {
    uint32_t network;   // host byte order, host bits zeroed
    uint8_t  depth;     // 1-31
    bool     used;
} protected_subnets[MAX_PROTECTED_SUBNETS];
static uint32_t protected_subnet_entries = 0;

// Statistics (use atomics for thread safety)
static uint64_t whitelist_hits = 0;
static uint64_t whitelist_cidr_hits = 0;
static uint64_t blacklist_hits = 0;
static uint64_t protected_hits = 0;
static uint64_t protected_misses = 0;

// CIDR entry counter (LPM doesn't provide this)
static uint32_t whitelist_cidr_entries = 0;

// Dummy value for hash table (we only need the key)
static const uint8_t PRESENT = 1;

// ==================== rte_flow Hardware Offload State ====================

// Maximum number of hardware blacklist rules per port
#define MAX_HW_BLACKLIST_RULES 4096

// Track rte_flow handles for each blacklisted IP
struct hw_blacklist_entry {
    uint32_t ip;                    // IP in network byte order (0 = empty)
    struct rte_flow *flow;          // rte_flow handle
};

// Per-port hardware offload state
struct hw_offload_state {
    bool enabled;
    struct hw_blacklist_entry entries[MAX_HW_BLACKLIST_RULES];
    uint32_t count;
    uint64_t add_success;
    uint64_t add_failure;
};

static struct hw_offload_state hw_state[RTE_MAX_ETHPORTS] = {{0}};

// LPM next-hop value (we just use 1 to indicate "whitelisted")
#define LPM_WHITELIST_NEXTHOP 1

// ==================== Initialization ====================

int ip_lists_init(const struct ip_lists_config *cfg) {
    struct rte_hash_parameters hash_params = {0};
    char hash_name[64];

    if (!cfg) {
        RTE_LOG(ERR, IPLIST, "Invalid config\n");
        return -1;
    }

    if (whitelist_hash != NULL || blacklist_hash != NULL || protected_hash != NULL) {
        RTE_LOG(WARNING, IPLIST, "IP lists already initialized\n");
        return 0;
    }

    // Save config
    memcpy(&config, cfg, sizeof(config));

    // Set defaults if not specified
    if (config.max_protected_entries == 0) {
        config.max_protected_entries = 1000;
    }
    if (config.max_whitelist_cidrs == 0) {
        config.max_whitelist_cidrs = 1000;
    }

    RTE_LOG(INFO, IPLIST, "Initializing IP lists (thread-safe):\n");
    RTE_LOG(INFO, IPLIST, "  Max whitelist: %u\n", config.max_whitelist_entries);
    RTE_LOG(INFO, IPLIST, "  Max whitelist CIDRs: %u\n", config.max_whitelist_cidrs);
    RTE_LOG(INFO, IPLIST, "  Max blacklist: %u\n", config.max_blacklist_entries);
    RTE_LOG(INFO, IPLIST, "  Max protected: %u\n", config.max_protected_entries);
    RTE_LOG(INFO, IPLIST, "  Enforce protected IPs: %s\n",
            config.enforce_protected_ips ? "yes" : "no");

    // Create whitelist hash table with thread safety
    snprintf(hash_name, sizeof(hash_name), "whitelist_%lu", 
             (unsigned long)rte_get_tsc_cycles());
    hash_params.name = hash_name;
    hash_params.entries = config.max_whitelist_entries;
    hash_params.key_len = sizeof(uint32_t);  // IP address
    hash_params.hash_func = rte_jhash;
    hash_params.hash_func_init_val = 0;
    hash_params.socket_id = rte_socket_id();
    // CRITICAL: Enable thread-safe concurrent access
    hash_params.extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY |
                             RTE_HASH_EXTRA_FLAGS_TRANS_MEM_SUPPORT;

    whitelist_hash = rte_hash_create(&hash_params);
    if (!whitelist_hash) {
        RTE_LOG(ERR, IPLIST, "Failed to create whitelist hash table\n");
        return -1;
    }

    // Create blacklist hash table with thread safety
    snprintf(hash_name, sizeof(hash_name), "blacklist_%lu",
             (unsigned long)rte_get_tsc_cycles());
    hash_params.name = hash_name;
    hash_params.entries = config.max_blacklist_entries;

    blacklist_hash = rte_hash_create(&hash_params);
    if (!blacklist_hash) {
        RTE_LOG(ERR, IPLIST, "Failed to create blacklist hash table\n");
        rte_hash_free(whitelist_hash);
        whitelist_hash = NULL;
        return -1;
    }

    // Create protected servers hash table with thread safety
    snprintf(hash_name, sizeof(hash_name), "protected_%lu",
             (unsigned long)rte_get_tsc_cycles());
    hash_params.name = hash_name;
    hash_params.entries = config.max_protected_entries;

    protected_hash = rte_hash_create(&hash_params);
    if (!protected_hash) {
        RTE_LOG(ERR, IPLIST, "Failed to create protected hash table\n");
        rte_hash_free(whitelist_hash);
        rte_hash_free(blacklist_hash);
        whitelist_hash = NULL;
        blacklist_hash = NULL;
        return -1;
    }

    // Create LPM table for CIDR whitelist
    struct rte_lpm_config lpm_config = {
        .max_rules = config.max_whitelist_cidrs,
        .number_tbl8s = 256,  // For /25 to /32 prefixes
        .flags = 0
    };

    char lpm_name[64];
    snprintf(lpm_name, sizeof(lpm_name), "wl_lpm_%lu",
             (unsigned long)rte_get_tsc_cycles());

    whitelist_lpm = rte_lpm_create(lpm_name, rte_socket_id(), &lpm_config);
    if (!whitelist_lpm) {
        RTE_LOG(ERR, IPLIST, "Failed to create whitelist LPM table\n");
        rte_hash_free(whitelist_hash);
        rte_hash_free(blacklist_hash);
        rte_hash_free(protected_hash);
        whitelist_hash = NULL;
        blacklist_hash = NULL;
        protected_hash = NULL;
        return -1;
    }

    // Create LPM table for CIDR protected subnets
    struct rte_lpm_config prot_lpm_config = {
        .max_rules = MAX_PROTECTED_SUBNETS,
        .number_tbl8s = 256,
        .flags = 0
    };
    char prot_lpm_name[64];
    snprintf(prot_lpm_name, sizeof(prot_lpm_name), "prot_lpm_%lu",
             (unsigned long)rte_get_tsc_cycles());
    protected_lpm = rte_lpm_create(prot_lpm_name, rte_socket_id(), &prot_lpm_config);
    if (!protected_lpm) {
        RTE_LOG(ERR, IPLIST, "Failed to create protected LPM table\n");
        rte_hash_free(whitelist_hash);
        rte_hash_free(blacklist_hash);
        rte_hash_free(protected_hash);
        rte_lpm_free(whitelist_lpm);
        whitelist_hash = NULL;
        blacklist_hash = NULL;
        protected_hash = NULL;
        whitelist_lpm = NULL;
        return -1;
    }
    memset(protected_subnets, 0, sizeof(protected_subnets));
    protected_subnet_entries = 0;

    RTE_LOG(INFO, IPLIST, "IP lists initialized successfully (thread-safe + LPM)\n");
    return 0;
}

void ip_lists_cleanup(void) {
    if (whitelist_hash) {
        rte_hash_free(whitelist_hash);
        whitelist_hash = NULL;
    }

    if (blacklist_hash) {
        rte_hash_free(blacklist_hash);
        blacklist_hash = NULL;
    }

    if (protected_hash) {
        rte_hash_free(protected_hash);
        protected_hash = NULL;
    }

    if (whitelist_lpm) {
        rte_lpm_free(whitelist_lpm);
        whitelist_lpm = NULL;
    }

    if (protected_lpm) {
        rte_lpm_free(protected_lpm);
        protected_lpm = NULL;
    }

    whitelist_cidr_entries = 0;
    memset(protected_subnets, 0, sizeof(protected_subnets));
    protected_subnet_entries = 0;

    RTE_LOG(INFO, IPLIST, "IP lists cleanup complete\n");
}

// ==================== Whitelist Operations ====================

int ip_whitelist_add(uint32_t ip, uint8_t mode) {
    int ret;

    if (!whitelist_hash) {
        return -1;
    }

    /* Store mode + 1 as data so 0 can mean "not found" in lookup */
    uintptr_t data_val = (uintptr_t)(mode + 1);
    lists_write_begin();
    ret = rte_hash_add_key_data(whitelist_hash, &ip, (void *)data_val);
    lists_write_end();
    if (ret < 0) {
        RTE_LOG(ERR, IPLIST, "Failed to add IP to whitelist: 0x%08x\n",
                rte_be_to_cpu_32(ip));
        return -1;
    }

    RTE_LOG(INFO, IPLIST, "Added IP to whitelist: %u.%u.%u.%u (mode=%u)\n",
            (rte_be_to_cpu_32(ip) >> 24) & 0xFF,
            (rte_be_to_cpu_32(ip) >> 16) & 0xFF,
            (rte_be_to_cpu_32(ip) >> 8) & 0xFF,
            rte_be_to_cpu_32(ip) & 0xFF, mode);

    return 0;
}

int ip_whitelist_remove(uint32_t ip) {
    int ret;

    if (!whitelist_hash) {
        return -1;
    }

    lists_write_begin();
    ret = rte_hash_del_key(whitelist_hash, &ip);
    lists_write_end();
    if (ret < 0) {
        return -1;  // Not found
    }

    RTE_LOG(INFO, IPLIST, "Removed IP from whitelist: %u.%u.%u.%u\n",
            (rte_be_to_cpu_32(ip) >> 24) & 0xFF,
            (rte_be_to_cpu_32(ip) >> 16) & 0xFF,
            (rte_be_to_cpu_32(ip) >> 8) & 0xFF,
            rte_be_to_cpu_32(ip) & 0xFF);

    return 0;
}

bool ip_whitelist_lookup(uint32_t ip, uint8_t *mode) {
    void *data;

    // 1. Check exact IP match (hash table) - network byte order
    if (whitelist_hash) {
        int ret = rte_hash_lookup_data(whitelist_hash, &ip, &data);
        if (ret >= 0) {
            __atomic_add_fetch(&whitelist_hits, 1, __ATOMIC_RELAXED);
            if (mode) {
                uintptr_t v = (uintptr_t)data;
                *mode = (v > 0) ? (uint8_t)(v - 1) : WL_MODE_BYPASS;
            }
            return true;
        }
    }

    // 2. Check CIDR prefix match (LPM) - host byte order
    if (whitelist_lpm) {
        uint32_t host_ip = rte_be_to_cpu_32(ip);
        uint32_t next_hop;
        int ret = rte_lpm_lookup(whitelist_lpm, host_ip, &next_hop);
        if (ret == 0 && next_hop == LPM_WHITELIST_NEXTHOP) {
            __atomic_add_fetch(&whitelist_cidr_hits, 1, __ATOMIC_RELAXED);
            if (mode) *mode = WL_MODE_BYPASS;
            return true;
        }
    }

    return false;
}

void ip_whitelist_clear(void) {
    if (whitelist_hash) {
        lists_write_begin();
        rte_hash_reset(whitelist_hash);
        lists_write_end();
        RTE_LOG(INFO, IPLIST, "Whitelist cleared\n");
    }
}

uint32_t ip_whitelist_count(void) {
    if (!whitelist_hash) {
        return 0;
    }
    return rte_hash_count(whitelist_hash);
}

// ==================== CIDR Whitelist Operations (LPM) ====================

int ip_whitelist_cidr_add(uint32_t ip_prefix, uint8_t depth) {
    if (!whitelist_lpm) {
        return -1;
    }

    if (depth < 1 || depth > 32) {
        RTE_LOG(ERR, IPLIST, "Invalid CIDR depth: %u (must be 1-32)\n", depth);
        return -1;
    }

    lists_write_begin();
    int ret = rte_lpm_add(whitelist_lpm, ip_prefix, depth, LPM_WHITELIST_NEXTHOP);
    if (ret >= 0) {
        __atomic_add_fetch(&whitelist_cidr_entries, 1, __ATOMIC_RELAXED);
    }
    lists_write_end();
    if (ret < 0) {
        RTE_LOG(ERR, IPLIST, "Failed to add CIDR to whitelist: %u.%u.%u.%u/%u (err=%d)\n",
                (ip_prefix >> 24) & 0xFF,
                (ip_prefix >> 16) & 0xFF,
                (ip_prefix >> 8) & 0xFF,
                ip_prefix & 0xFF,
                depth, ret);
        return -1;
    }

    RTE_LOG(INFO, IPLIST, "Added CIDR to whitelist: %u.%u.%u.%u/%u\n",
            (ip_prefix >> 24) & 0xFF,
            (ip_prefix >> 16) & 0xFF,
            (ip_prefix >> 8) & 0xFF,
            ip_prefix & 0xFF,
            depth);

    return 0;
}

int ip_whitelist_cidr_remove(uint32_t ip_prefix, uint8_t depth) {
    if (!whitelist_lpm) {
        return -1;
    }

    if (depth < 1 || depth > 32) {
        return -1;
    }

    lists_write_begin();
    int ret = rte_lpm_delete(whitelist_lpm, ip_prefix, depth);
    if (ret >= 0) {
        __atomic_sub_fetch(&whitelist_cidr_entries, 1, __ATOMIC_RELAXED);
    }
    lists_write_end();
    if (ret < 0) {
        return -1;  // Not found
    }

    RTE_LOG(INFO, IPLIST, "Removed CIDR from whitelist: %u.%u.%u.%u/%u\n",
            (ip_prefix >> 24) & 0xFF,
            (ip_prefix >> 16) & 0xFF,
            (ip_prefix >> 8) & 0xFF,
            ip_prefix & 0xFF,
            depth);

    return 0;
}

bool ip_whitelist_cidr_lookup(uint32_t ip) {
    if (!whitelist_lpm) {
        return false;
    }

    uint32_t next_hop;
    int ret = rte_lpm_lookup(whitelist_lpm, ip, &next_hop);
    if (ret == 0 && next_hop == LPM_WHITELIST_NEXTHOP) {
        __atomic_add_fetch(&whitelist_cidr_hits, 1, __ATOMIC_RELAXED);
        return true;
    }

    return false;
}

void ip_whitelist_cidr_clear(void) {
    if (whitelist_lpm) {
        lists_write_begin();
        rte_lpm_delete_all(whitelist_lpm);
        __atomic_store_n(&whitelist_cidr_entries, 0, __ATOMIC_RELAXED);
        lists_write_end();
        RTE_LOG(INFO, IPLIST, "CIDR whitelist cleared\n");
    }
}

uint32_t ip_whitelist_cidr_count(void) {
    return __atomic_load_n(&whitelist_cidr_entries, __ATOMIC_RELAXED);
}

// ==================== Blacklist Operations ====================

int ip_blacklist_add(uint32_t ip) {
    int ret;

    if (!blacklist_hash) {
        return -1;
    }

    lists_write_begin();
    ret = rte_hash_add_key_data(blacklist_hash, &ip, (void *)(uintptr_t)PRESENT);
    lists_write_end();
    if (ret < 0) {
        RTE_LOG(ERR, IPLIST, "Failed to add IP to blacklist: 0x%08x\n",
                rte_be_to_cpu_32(ip));
        return -1;
    }

    RTE_LOG(INFO, IPLIST, "Added IP to blacklist: %u.%u.%u.%u\n",
            (rte_be_to_cpu_32(ip) >> 24) & 0xFF,
            (rte_be_to_cpu_32(ip) >> 16) & 0xFF,
            (rte_be_to_cpu_32(ip) >> 8) & 0xFF,
            rte_be_to_cpu_32(ip) & 0xFF);

    return 0;
}

int ip_blacklist_remove(uint32_t ip) {
    int ret;

    if (!blacklist_hash) {
        return -1;
    }

    lists_write_begin();
    ret = rte_hash_del_key(blacklist_hash, &ip);
    lists_write_end();
    if (ret < 0) {
        return -1;  // Not found
    }

    RTE_LOG(INFO, IPLIST, "Removed IP from blacklist: %u.%u.%u.%u\n",
            (rte_be_to_cpu_32(ip) >> 24) & 0xFF,
            (rte_be_to_cpu_32(ip) >> 16) & 0xFF,
            (rte_be_to_cpu_32(ip) >> 8) & 0xFF,
            rte_be_to_cpu_32(ip) & 0xFF);

    return 0;
}

bool ip_blacklist_lookup(uint32_t ip) {
    void *data;

    if (!blacklist_hash) {
        return false;
    }

    int ret = rte_hash_lookup_data(blacklist_hash, &ip, &data);
    if (ret >= 0) {
        __atomic_add_fetch(&blacklist_hits, 1, __ATOMIC_RELAXED);
        return true;
    }

    return false;
}

void ip_blacklist_clear(void) {
    if (blacklist_hash) {
        lists_write_begin();
        rte_hash_reset(blacklist_hash);
        lists_write_end();
        RTE_LOG(INFO, IPLIST, "Blacklist cleared\n");
    }
}

uint32_t ip_blacklist_count(void) {
    if (!blacklist_hash) {
        return 0;
    }
    return rte_hash_count(blacklist_hash);
}

// ==================== Protected Server Operations ====================

int ip_protected_add(uint32_t ip) {
    int ret;

    if (!protected_hash) {
        return -1;
    }

    lists_write_begin();
    ret = rte_hash_add_key_data(protected_hash, &ip, (void *)(uintptr_t)PRESENT);
    if (ret < 0) {
        lists_write_end();
        RTE_LOG(ERR, IPLIST, "Failed to add IP to protected list: 0x%08x\n",
                rte_be_to_cpu_32(ip));
        return -1;
    }

    // Register for per-IP feature tracking (if initialized). Its table has
    // one writer at a time too, so the registration stays under the lock.
    bool features_on = per_ip_features_is_initialized();
    int reg_ret = features_on ? per_ip_features_register(ip) : 0;
    lists_write_end();
    if (features_on) {
        if (reg_ret < 0) {
            RTE_LOG(ERR, IPLIST, "FAILED to register IP for per-IP features: %u.%u.%u.%u\n",
                    (rte_be_to_cpu_32(ip) >> 24) & 0xFF,
                    (rte_be_to_cpu_32(ip) >> 16) & 0xFF,
                    (rte_be_to_cpu_32(ip) >> 8) & 0xFF,
                    rte_be_to_cpu_32(ip) & 0xFF);
        } else {
            RTE_LOG(INFO, IPLIST, "Registered IP for per-IP features: %u.%u.%u.%u\n",
                    (rte_be_to_cpu_32(ip) >> 24) & 0xFF,
                    (rte_be_to_cpu_32(ip) >> 16) & 0xFF,
                    (rte_be_to_cpu_32(ip) >> 8) & 0xFF,
                    rte_be_to_cpu_32(ip) & 0xFF);
        }
    } else {
        RTE_LOG(WARNING, IPLIST, "per_ip_features NOT initialized when adding: %u.%u.%u.%u\n",
                (rte_be_to_cpu_32(ip) >> 24) & 0xFF,
                (rte_be_to_cpu_32(ip) >> 16) & 0xFF,
                (rte_be_to_cpu_32(ip) >> 8) & 0xFF,
                rte_be_to_cpu_32(ip) & 0xFF);
    }

    RTE_LOG(INFO, IPLIST, "Added protected server IP: %u.%u.%u.%u\n",
            (rte_be_to_cpu_32(ip) >> 24) & 0xFF,
            (rte_be_to_cpu_32(ip) >> 16) & 0xFF,
            (rte_be_to_cpu_32(ip) >> 8) & 0xFF,
            rte_be_to_cpu_32(ip) & 0xFF);

    return 0;
}

int ip_protected_remove(uint32_t ip) {
    int ret;

    if (!protected_hash) {
        return -1;
    }

    lists_write_begin();
    ret = rte_hash_del_key(protected_hash, &ip);
    // Unregister from per-IP feature tracking (if initialized)
    if (ret >= 0 && per_ip_features_is_initialized()) {
        per_ip_features_unregister(ip);
    }
    lists_write_end();
    if (ret < 0) {
        return -1;  // Not found
    }

    RTE_LOG(INFO, IPLIST, "Removed protected server IP: %u.%u.%u.%u\n",
            (rte_be_to_cpu_32(ip) >> 24) & 0xFF,
            (rte_be_to_cpu_32(ip) >> 16) & 0xFF,
            (rte_be_to_cpu_32(ip) >> 8) & 0xFF,
            rte_be_to_cpu_32(ip) & 0xFF);

    return 0;
}

bool ip_protected_lookup(uint32_t ip) {
    void *data;

    if (!protected_hash) {
        return false;
    }

    int ret = rte_hash_lookup_data(protected_hash, &ip, &data);
    if (ret >= 0) {
        __atomic_add_fetch(&protected_hits, 1, __ATOMIC_RELAXED);
        return true;
    }

    __atomic_add_fetch(&protected_misses, 1, __ATOMIC_RELAXED);
    return false;
}

void ip_protected_clear(void) {
    if (protected_hash) {
        lists_write_begin();
        rte_hash_reset(protected_hash);
        lists_write_end();
        RTE_LOG(INFO, IPLIST, "Protected list cleared\n");
    }
}

uint32_t ip_protected_count(void) {
    if (!protected_hash) {
        return 0;
    }
    return rte_hash_count(protected_hash);
}

// ==================== Protected Subnets (CIDR aggregate tracking) ====================

/** Host-order network mask for a prefix length (depth 1-31). */
static inline uint32_t prefix_mask_host(uint8_t depth) {
    if (depth == 0) return 0u;
    if (depth >= 32) return 0xFFFFFFFFu;
    return 0xFFFFFFFFu << (32 - depth);
}

/** Find the side-table slot for a (network, depth), or -1. */
static int protected_subnet_find(uint32_t network, uint8_t depth) {
    for (int i = 0; i < MAX_PROTECTED_SUBNETS; i++) {
        if (protected_subnets[i].used &&
            protected_subnets[i].network == network &&
            protected_subnets[i].depth == depth) {
            return i;
        }
    }
    return -1;
}

// The writers of the protected-subnet side table and LPM, under lists_write_lock
static int protected_subnet_add_locked(uint32_t ip_prefix, uint8_t depth) {
    if (!protected_lpm) {
        return -1;
    }
    // /32 is an exact protected IP -- use ip_protected_add() for that.
    if (depth < 1 || depth > 31) {
        RTE_LOG(ERR, IPLIST, "Invalid protected subnet depth: %u (must be 1-31)\n", depth);
        return -1;
    }

    uint32_t network = ip_prefix & prefix_mask_host(depth);  // host order

    // Idempotent: already present?
    if (protected_subnet_find(network, depth) >= 0) {
        return 0;
    }

    // Find a free side-table slot.
    int slot = -1;
    for (int i = 0; i < MAX_PROTECTED_SUBNETS; i++) {
        if (!protected_subnets[i].used) { slot = i; break; }
    }
    if (slot < 0) {
        RTE_LOG(ERR, IPLIST, "Protected subnet table full (max=%d)\n", MAX_PROTECTED_SUBNETS);
        return -1;
    }

    // Publish the side-table slot BEFORE the LPM entry that makes it reachable.
    // The datapath reads protected_subnets[next_hop-1] after an LPM hit, so the
    // slot's fields must be visible before the LPM entry is. rte_smp_wmb() orders
    // the two stores on weakly-ordered archs (e.g. ARM); on x86-TSO it is just a
    // compiler barrier. Without it the datapath could observe used==true with a
    // stale .network.
    protected_subnets[slot].network = network;
    protected_subnets[slot].depth = depth;
    protected_subnets[slot].used = true;
    rte_smp_wmb();

    // next_hop encodes slot+1 (LPM next_hop 0 would be indistinguishable from miss).
    int ret = rte_lpm_add(protected_lpm, network, depth, (uint32_t)(slot + 1));
    if (ret < 0) {
        protected_subnets[slot].used = false;  // roll back the reserved slot
        RTE_LOG(ERR, IPLIST, "Failed to add protected subnet %u.%u.%u.%u/%u (err=%d)\n",
                (network >> 24) & 0xFF, (network >> 16) & 0xFF,
                (network >> 8) & 0xFF, network & 0xFF, depth, ret);
        return -1;
    }
    protected_subnet_entries++;

    // Aggregate the whole subnet into ONE per-IP feature slot keyed by its network
    // address (network byte order, to match dst_ip keys from the datapath).
    //
    // NOTE: this slot's HLLs see the UNION of sources/ports across the whole CIDR,
    // so the cumulative (never-reset) `unique_src_ips` saturates faster than a /32
    // slot and the ABSOLUTE cardinality feature goes flat-high over the slot's life.
    // The delta feature `new_srcip_rate` (L2_FEAT_NEW_SRCIP_RATE) is the robust
    // signal for a subnet slot; windowing the HLL is a broader pre-existing change.
    if (per_ip_features_is_initialized()) {
        if (per_ip_features_register(rte_cpu_to_be_32(network)) < 0) {
            RTE_LOG(WARNING, IPLIST, "Protected subnet added but per-IP slot register failed: "
                    "%u.%u.%u.%u/%u\n",
                    (network >> 24) & 0xFF, (network >> 16) & 0xFF,
                    (network >> 8) & 0xFF, network & 0xFF, depth);
        }
    }

    RTE_LOG(INFO, IPLIST, "Added protected subnet: %u.%u.%u.%u/%u\n",
            (network >> 24) & 0xFF, (network >> 16) & 0xFF,
            (network >> 8) & 0xFF, network & 0xFF, depth);
    return 0;
}

static int protected_subnet_remove_locked(uint32_t ip_prefix, uint8_t depth) {
    if (!protected_lpm) {
        return -1;
    }
    if (depth < 1 || depth > 31) {
        return -1;
    }

    uint32_t network = ip_prefix & prefix_mask_host(depth);
    int slot = protected_subnet_find(network, depth);
    if (slot < 0) {
        return -1;  // Not found
    }

    rte_lpm_delete(protected_lpm, network, depth);
    protected_subnets[slot].used = false;
    if (protected_subnet_entries > 0) protected_subnet_entries--;

    if (per_ip_features_is_initialized()) {
        per_ip_features_unregister(rte_cpu_to_be_32(network));
    }

    RTE_LOG(INFO, IPLIST, "Removed protected subnet: %u.%u.%u.%u/%u\n",
            (network >> 24) & 0xFF, (network >> 16) & 0xFF,
            (network >> 8) & 0xFF, network & 0xFF, depth);
    return 0;
}

int ip_protected_subnet_add(uint32_t ip_prefix, uint8_t depth) {
    lists_write_begin();
    int ret = protected_subnet_add_locked(ip_prefix, depth);
    lists_write_end();
    return ret;
}

int ip_protected_subnet_remove(uint32_t ip_prefix, uint8_t depth) {
    lists_write_begin();
    int ret = protected_subnet_remove_locked(ip_prefix, depth);
    lists_write_end();
    return ret;
}

bool ip_protected_subnet_lookup(uint32_t dst_ip, uint32_t *net_be_out) {
    if (!protected_lpm) {
        return false;
    }
    uint32_t host_ip = rte_be_to_cpu_32(dst_ip);
    uint32_t next_hop = 0;
    if (rte_lpm_lookup(protected_lpm, host_ip, &next_hop) != 0) {
        return false;  // no match
    }
    uint32_t slot = next_hop - 1;  // we stored slot+1
    if (slot >= MAX_PROTECTED_SUBNETS || !protected_subnets[slot].used) {
        return false;  // stale/inconsistent next_hop
    }
    if (net_be_out) {
        *net_be_out = rte_cpu_to_be_32(protected_subnets[slot].network);
    }
    return true;
}

static void protected_subnet_clear_locked(void) {
    if (!protected_lpm) {
        return;
    }
    for (int i = 0; i < MAX_PROTECTED_SUBNETS; i++) {
        if (protected_subnets[i].used) {
            rte_lpm_delete(protected_lpm, protected_subnets[i].network,
                           protected_subnets[i].depth);
            if (per_ip_features_is_initialized()) {
                per_ip_features_unregister(rte_cpu_to_be_32(protected_subnets[i].network));
            }
            protected_subnets[i].used = false;
        }
    }
    protected_subnet_entries = 0;
    RTE_LOG(INFO, IPLIST, "Protected subnets cleared\n");
}

void ip_protected_subnet_clear(void) {
    lists_write_begin();
    protected_subnet_clear_locked();
    lists_write_end();
}

uint32_t ip_protected_subnet_count(void) {
    return protected_subnet_entries;
}

bool ip_protected_enforcement_enabled(void) {
    return config.enforce_protected_ips;
}

void ip_protected_set_enforcement(bool enabled) {
    config.enforce_protected_ips = enabled;
    RTE_LOG(INFO, IPLIST, "Protected IP enforcement %s\n",
            enabled ? "ENABLED" : "DISABLED");
}

// ==================== Statistics ====================

void ip_lists_get_stats(uint32_t *whitelist_count, uint32_t *blacklist_count,
                        uint64_t *wl_hits, uint64_t *bl_hits) {
    if (whitelist_count) {
        *whitelist_count = ip_whitelist_count();
    }
    if (blacklist_count) {
        *blacklist_count = ip_blacklist_count();
    }
    if (wl_hits) {
        *wl_hits = __atomic_load_n(&whitelist_hits, __ATOMIC_RELAXED);
    }
    if (bl_hits) {
        *bl_hits = __atomic_load_n(&blacklist_hits, __ATOMIC_RELAXED);
    }
}

void ip_lists_print_stats(void) {
    printf("  IP Lists Statistics:\n");
    printf("    Whitelist (exact): %u entries, %lu hits\n",
           ip_whitelist_count(), __atomic_load_n(&whitelist_hits, __ATOMIC_RELAXED));
    printf("    Whitelist (CIDR):  %u entries, %lu hits\n",
           ip_whitelist_cidr_count(), __atomic_load_n(&whitelist_cidr_hits, __ATOMIC_RELAXED));
    printf("    Blacklist: %u entries, %lu hits\n",
           ip_blacklist_count(), __atomic_load_n(&blacklist_hits, __ATOMIC_RELAXED));
    printf("    Protected: %u entries, %lu hits, %lu misses\n",
           ip_protected_count(),
           __atomic_load_n(&protected_hits, __ATOMIC_RELAXED),
           __atomic_load_n(&protected_misses, __ATOMIC_RELAXED));
    printf("    Enforce protected: %s\n",
           config.enforce_protected_ips ? "yes" : "no");

    // Print hardware offload stats for active ports
    for (uint16_t port = 0; port < RTE_MAX_ETHPORTS; port++) {
        if (hw_state[port].enabled) {
            printf("    HW Offload (port %u): %u rules, %lu created, %lu failed\n",
                   port, hw_state[port].count,
                   hw_state[port].add_success, hw_state[port].add_failure);
        }
    }
}

// ==================== rte_flow Hardware Offload Implementation ====================

/**
 * Create an rte_flow DROP rule for a source IP
 */
static struct rte_flow *create_drop_flow(uint16_t port_id, uint32_t src_ip) {
    struct rte_flow_attr attr = {
        .group = 0,
        .priority = 0,  // Highest priority
        .ingress = 1,
        .egress = 0,
        .transfer = 0,
    };

    // Match pattern: Ethernet -> IPv4 (source IP)
    struct rte_flow_item_eth eth_spec = {0};
    struct rte_flow_item_eth eth_mask = {0};
    eth_spec.hdr.ether_type = RTE_BE16(RTE_ETHER_TYPE_IPV4);
    eth_mask.hdr.ether_type = 0xFFFF;

    struct rte_flow_item_ipv4 ipv4_spec = {0};
    struct rte_flow_item_ipv4 ipv4_mask = {0};
    ipv4_spec.hdr.src_addr = src_ip;  // Already in network byte order
    ipv4_mask.hdr.src_addr = 0xFFFFFFFF;  // Exact match

    struct rte_flow_item pattern[] = {
        {
            .type = RTE_FLOW_ITEM_TYPE_ETH,
            .spec = &eth_spec,
            .mask = &eth_mask,
            .last = NULL,
        },
        {
            .type = RTE_FLOW_ITEM_TYPE_IPV4,
            .spec = &ipv4_spec,
            .mask = &ipv4_mask,
            .last = NULL,
        },
        {
            .type = RTE_FLOW_ITEM_TYPE_END,
        },
    };

    // Action: DROP
    struct rte_flow_action actions[] = {
        {
            .type = RTE_FLOW_ACTION_TYPE_DROP,
        },
        {
            .type = RTE_FLOW_ACTION_TYPE_END,
        },
    };

    struct rte_flow_error error;
    struct rte_flow *flow;

    // Validate the flow first
    int ret = rte_flow_validate(port_id, &attr, pattern, actions, &error);
    if (ret != 0) {
        RTE_LOG(DEBUG, IPLIST, "rte_flow validate failed: %s (type=%d)\n",
                error.message ? error.message : "unknown", error.type);
        return NULL;
    }

    // Create the flow
    flow = rte_flow_create(port_id, &attr, pattern, actions, &error);
    if (flow == NULL) {
        RTE_LOG(DEBUG, IPLIST, "rte_flow create failed: %s (type=%d)\n",
                error.message ? error.message : "unknown", error.type);
        return NULL;
    }

    return flow;
}

/**
 * Find slot for IP in hardware entries (or find existing entry)
 */
static int find_hw_entry_slot(uint16_t port_id, uint32_t ip, bool find_existing) {
    struct hw_offload_state *state = &hw_state[port_id];

    if (find_existing) {
        // Look for existing entry with this IP
        for (uint32_t i = 0; i < MAX_HW_BLACKLIST_RULES; i++) {
            if (state->entries[i].ip == ip) {
                return (int)i;
            }
        }
        return -1;  // Not found
    } else {
        // Look for empty slot
        for (uint32_t i = 0; i < MAX_HW_BLACKLIST_RULES; i++) {
            if (state->entries[i].ip == 0) {
                return (int)i;
            }
        }
        return -1;  // No space
    }
}

int ip_blacklist_hw_offload_init(uint16_t port_id) {
    if (port_id >= RTE_MAX_ETHPORTS) {
        return -1;
    }

    if (hw_state[port_id].enabled) {
        RTE_LOG(WARNING, IPLIST, "Hardware offload already enabled for port %u\n", port_id);
        return 0;
    }

    // Test if the NIC supports rte_flow with DROP action
    // Create a dummy rule to test capability
    struct rte_flow_attr attr = { .ingress = 1 };
    struct rte_flow_item_ipv4 ipv4_spec = { .hdr.src_addr = 0x01020304 };
    struct rte_flow_item_ipv4 ipv4_mask = { .hdr.src_addr = 0xFFFFFFFF };

    struct rte_flow_item pattern[] = {
        { .type = RTE_FLOW_ITEM_TYPE_ETH },
        { .type = RTE_FLOW_ITEM_TYPE_IPV4, .spec = &ipv4_spec, .mask = &ipv4_mask },
        { .type = RTE_FLOW_ITEM_TYPE_END },
    };

    struct rte_flow_action actions[] = {
        { .type = RTE_FLOW_ACTION_TYPE_DROP },
        { .type = RTE_FLOW_ACTION_TYPE_END },
    };

    struct rte_flow_error error;
    int ret = rte_flow_validate(port_id, &attr, pattern, actions, &error);
    if (ret != 0) {
        RTE_LOG(WARNING, IPLIST, "Port %u: NIC doesn't support rte_flow DROP rules: %s\n",
                port_id, error.message ? error.message : "unknown");
        RTE_LOG(INFO, IPLIST, "Port %u: Will use software-only blacklist\n", port_id);
        return -1;
    }

    // Initialize state
    memset(&hw_state[port_id], 0, sizeof(hw_state[port_id]));
    hw_state[port_id].enabled = true;

    RTE_LOG(INFO, IPLIST, "Port %u: Hardware blacklist offload enabled (max %d rules)\n",
            port_id, MAX_HW_BLACKLIST_RULES);

    return 0;
}

void ip_blacklist_hw_offload_cleanup(uint16_t port_id) {
    if (port_id >= RTE_MAX_ETHPORTS || !hw_state[port_id].enabled) {
        return;
    }

    struct hw_offload_state *state = &hw_state[port_id];
    struct rte_flow_error error;

    // Destroy all active flows
    for (uint32_t i = 0; i < MAX_HW_BLACKLIST_RULES; i++) {
        if (state->entries[i].flow != NULL) {
            rte_flow_destroy(port_id, state->entries[i].flow, &error);
            state->entries[i].flow = NULL;
            state->entries[i].ip = 0;
        }
    }

    uint32_t removed = state->count;
    state->count = 0;
    state->enabled = false;

    RTE_LOG(INFO, IPLIST, "Port %u: Hardware offload cleanup complete (%u rules removed)\n",
            port_id, removed);
}

bool ip_blacklist_hw_offload_enabled(uint16_t port_id) {
    if (port_id >= RTE_MAX_ETHPORTS) {
        return false;
    }
    return hw_state[port_id].enabled;
}

int ip_blacklist_add_hw(uint16_t port_id, uint32_t ip) {
    // Always add to software blacklist first
    if (ip_blacklist_add(ip) < 0) {
        return -1;
    }

    // If hardware offload not enabled/available, that's OK - software handles it
    if (port_id >= RTE_MAX_ETHPORTS || !hw_state[port_id].enabled) {
        return 0;
    }

    struct hw_offload_state *state = &hw_state[port_id];

    // Check if already in hardware
    if (find_hw_entry_slot(port_id, ip, true) >= 0) {
        return 0;  // Already offloaded
    }

    // Find empty slot
    int slot = find_hw_entry_slot(port_id, ip, false);
    if (slot < 0) {
        RTE_LOG(WARNING, IPLIST, "Port %u: Hardware blacklist full (%u rules), software-only for IP\n",
                port_id, MAX_HW_BLACKLIST_RULES);
        return 0;  // Not an error - software blacklist handles it
    }

    // Create hardware rule
    struct rte_flow *flow = create_drop_flow(port_id, ip);
    if (flow == NULL) {
        state->add_failure++;
        // Not a critical error - software blacklist is the fallback
        RTE_LOG(DEBUG, IPLIST, "Port %u: Hardware rule creation failed, using software\n", port_id);
        return 0;
    }

    // Store the flow handle
    state->entries[slot].ip = ip;
    state->entries[slot].flow = flow;
    state->count++;
    state->add_success++;

    RTE_LOG(DEBUG, IPLIST, "Port %u: Added hardware DROP rule for %u.%u.%u.%u\n",
            port_id,
            (rte_be_to_cpu_32(ip) >> 24) & 0xFF,
            (rte_be_to_cpu_32(ip) >> 16) & 0xFF,
            (rte_be_to_cpu_32(ip) >> 8) & 0xFF,
            rte_be_to_cpu_32(ip) & 0xFF);

    return 0;
}

int ip_blacklist_remove_hw(uint16_t port_id, uint32_t ip) {
    // Always remove from software blacklist
    int sw_ret = ip_blacklist_remove(ip);

    // Remove hardware rule if present
    if (port_id < RTE_MAX_ETHPORTS && hw_state[port_id].enabled) {
        struct hw_offload_state *state = &hw_state[port_id];
        int slot = find_hw_entry_slot(port_id, ip, true);

        if (slot >= 0 && state->entries[slot].flow != NULL) {
            struct rte_flow_error error;
            rte_flow_destroy(port_id, state->entries[slot].flow, &error);
            state->entries[slot].flow = NULL;
            state->entries[slot].ip = 0;
            state->count--;

            RTE_LOG(DEBUG, IPLIST, "Port %u: Removed hardware DROP rule for %u.%u.%u.%u\n",
                    port_id,
                    (rte_be_to_cpu_32(ip) >> 24) & 0xFF,
                    (rte_be_to_cpu_32(ip) >> 16) & 0xFF,
                    (rte_be_to_cpu_32(ip) >> 8) & 0xFF,
                    rte_be_to_cpu_32(ip) & 0xFF);
        }
    }

    return sw_ret;
}

void ip_blacklist_hw_get_stats(uint16_t port_id, uint32_t *hw_rules,
                               uint64_t *hw_add_ok, uint64_t *hw_add_fail) {
    if (port_id >= RTE_MAX_ETHPORTS || !hw_state[port_id].enabled) {
        if (hw_rules) *hw_rules = 0;
        if (hw_add_ok) *hw_add_ok = 0;
        if (hw_add_fail) *hw_add_fail = 0;
        return;
    }

    struct hw_offload_state *state = &hw_state[port_id];
    if (hw_rules) *hw_rules = state->count;
    if (hw_add_ok) *hw_add_ok = state->add_success;
    if (hw_add_fail) *hw_add_fail = state->add_failure;
}

// ==================== Get All IPs (for iteration) ====================

uint32_t ip_protected_get_all(uint32_t *ips, uint32_t max_ips) {
    if (!protected_hash || !ips || max_ips == 0) {
        return 0;
    }

    uint32_t count = 0;
    uint32_t iter = 0;
    const void *key;
    void *data;

    while (rte_hash_iterate(protected_hash, &key, &data, &iter) >= 0) {
        if (count >= max_ips) break;
        ips[count++] = *(const uint32_t *)key;
    }

    return count;
}

uint32_t ip_whitelist_get_all(uint32_t *ips, uint32_t max_ips) {
    if (!whitelist_hash || !ips || max_ips == 0) {
        return 0;
    }

    uint32_t count = 0;
    uint32_t iter = 0;
    const void *key;
    void *data;

    while (rte_hash_iterate(whitelist_hash, &key, &data, &iter) >= 0) {
        if (count >= max_ips) break;
        ips[count++] = *(const uint32_t *)key;
    }

    return count;
}

uint32_t ip_blacklist_get_all(uint32_t *ips, uint32_t max_ips) {
    if (!blacklist_hash || !ips || max_ips == 0) {
        return 0;
    }

    uint32_t count = 0;
    uint32_t iter = 0;
    const void *key;
    void *data;

    while (rte_hash_iterate(blacklist_hash, &key, &data, &iter) >= 0) {
        if (count >= max_ips) break;
        ips[count++] = *(const uint32_t *)key;
    }

    return count;
}

// ==================== Persistence (Save/Load) ====================

#include "cJSON.h"
#include <stdio.h>
#include <arpa/inet.h>

// Helper: Convert IP (network byte order) to string
static void ip_to_str(uint32_t ip, char *buf, size_t len) {
    uint32_t host_ip = rte_be_to_cpu_32(ip);
    snprintf(buf, len, "%u.%u.%u.%u",
             (host_ip >> 24) & 0xFF,
             (host_ip >> 16) & 0xFF,
             (host_ip >> 8) & 0xFF,
             host_ip & 0xFF);
}

// Helper: Parse IP string to network byte order
static uint32_t str_to_ip(const char *str) {
    struct in_addr addr;
    if (inet_aton(str, &addr) == 0) {
        return 0;  // Invalid
    }
    return addr.s_addr;  // Already network byte order
}

int ip_lists_save(const char *path) {
    if (!path) {
        path = IP_LISTS_DEFAULT_PATH;
    }

    cJSON *root = cJSON_CreateObject();
    if (!root) {
        RTE_LOG(ERR, IPLIST, "Failed to create JSON object\n");
        return -1;
    }

    // Create arrays for each list
    cJSON *protected_arr = cJSON_CreateArray();
    cJSON *whitelist_arr = cJSON_CreateArray();
    cJSON *blacklist_arr = cJSON_CreateArray();

    // Get protected IPs
    uint32_t ips[10000];
    char ip_str[32];

    // Preserve profile objects another writer (the backend) may have stored for
    // protected IPs. The C layer only knows the bare IP, so without this a C-side
    // save would clobber the backend's "{ip, profile, ...}" objects with plain
    // strings and the next CMD_RELOAD_PROFILES would find no profile data.
    cJSON *existing_root = NULL;
    cJSON *existing_protected = NULL;  // borrowed from existing_root
    {
        FILE *ef = fopen(path, "r");
        if (ef) {
            fseek(ef, 0, SEEK_END);
            long esz = ftell(ef);
            fseek(ef, 0, SEEK_SET);
            if (esz > 0) {
                char *ebuf = malloc((size_t)esz + 1);
                if (ebuf) {
                    size_t er = fread(ebuf, 1, (size_t)esz, ef);
                    ebuf[er] = '\0';
                    existing_root = cJSON_Parse(ebuf);
                    free(ebuf);
                    if (existing_root) {
                        existing_protected = cJSON_GetObjectItem(existing_root, "protected_ips");
                    }
                }
            }
            fclose(ef);
        }
    }

    uint32_t count = ip_protected_get_all(ips, 10000);
    for (uint32_t i = 0; i < count; i++) {
        ip_to_str(ips[i], ip_str, sizeof(ip_str));

        // Reuse an existing object entry (with profile) for this IP if present.
        cJSON *preserved = NULL;
        if (existing_protected && cJSON_IsArray(existing_protected)) {
            cJSON *e;
            cJSON_ArrayForEach(e, existing_protected) {
                if (!cJSON_IsObject(e)) continue;
                cJSON *eip = cJSON_GetObjectItem(e, "ip");
                if (eip && cJSON_IsString(eip) && strcmp(eip->valuestring, ip_str) == 0) {
                    preserved = e;
                    break;
                }
            }
        }

        if (preserved) {
            cJSON_AddItemToArray(protected_arr, cJSON_Duplicate(preserved, 1));
        } else {
            cJSON_AddItemToArray(protected_arr, cJSON_CreateString(ip_str));
        }
    }
    if (existing_root) {
        cJSON_Delete(existing_root);  // duplicates already copied into protected_arr
    }
    cJSON_AddItemToObject(root, "protected_ips", protected_arr);

    // Protected subnets (CIDR) -- serialized as "network/depth" strings.
    cJSON *protected_subnets_arr = cJSON_CreateArray();
    for (int i = 0; i < MAX_PROTECTED_SUBNETS; i++) {
        if (!protected_subnets[i].used) continue;
        uint32_t net = protected_subnets[i].network;  // host order
        snprintf(ip_str, sizeof(ip_str), "%u.%u.%u.%u/%u",
                 (net >> 24) & 0xFF, (net >> 16) & 0xFF,
                 (net >> 8) & 0xFF, net & 0xFF, protected_subnets[i].depth);
        cJSON_AddItemToArray(protected_subnets_arr, cJSON_CreateString(ip_str));
    }
    cJSON_AddItemToObject(root, "protected_subnets", protected_subnets_arr);

    // Get whitelist IPs
    count = ip_whitelist_get_all(ips, 10000);
    for (uint32_t i = 0; i < count; i++) {
        ip_to_str(ips[i], ip_str, sizeof(ip_str));
        cJSON_AddItemToArray(whitelist_arr, cJSON_CreateString(ip_str));
    }
    cJSON_AddItemToObject(root, "whitelist_ips", whitelist_arr);

    // Get blacklist IPs
    count = ip_blacklist_get_all(ips, 10000);
    for (uint32_t i = 0; i < count; i++) {
        ip_to_str(ips[i], ip_str, sizeof(ip_str));
        cJSON_AddItemToArray(blacklist_arr, cJSON_CreateString(ip_str));
    }
    cJSON_AddItemToObject(root, "blacklist_ips", blacklist_arr);

    // Write to file
    char *json_str = cJSON_Print(root);
    cJSON_Delete(root);

    if (!json_str) {
        RTE_LOG(ERR, IPLIST, "Failed to serialize JSON\n");
        return -1;
    }

    FILE *f = fopen(path, "w");
    if (!f) {
        RTE_LOG(ERR, IPLIST, "Failed to open %s for writing: %s\n", path, strerror(errno));
        free(json_str);
        return -1;
    }

    fputs(json_str, f);
    fclose(f);
    free(json_str);

    RTE_LOG(INFO, IPLIST, "Saved IP lists to %s (protected=%u, whitelist=%u, blacklist=%u)\n",
            path, ip_protected_count(), ip_whitelist_count(), ip_blacklist_count());

    return 0;
}

int ip_lists_load(const char *path) {
    if (!path) {
        path = IP_LISTS_DEFAULT_PATH;
    }

    FILE *f = fopen(path, "r");
    if (!f) {
        // File doesn't exist is OK - just means no saved IPs yet
        RTE_LOG(INFO, IPLIST, "No IP lists file at %s (will be created on first save)\n", path);
        return 0;
    }

    // Read file
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *json_str = malloc(size + 1);
    if (!json_str) {
        fclose(f);
        return -1;
    }

    size_t read = fread(json_str, 1, size, f);
    fclose(f);
    json_str[read] = '\0';

    // Parse JSON
    cJSON *root = cJSON_Parse(json_str);
    free(json_str);

    if (!root) {
        RTE_LOG(ERR, IPLIST, "Failed to parse %s: %s\n", path,
                cJSON_GetErrorPtr() ? cJSON_GetErrorPtr() : "unknown error");
        return -1;
    }

    uint32_t loaded_protected = 0, loaded_whitelist = 0, loaded_blacklist = 0;

    // Load protected IPs
    cJSON *arr = cJSON_GetObjectItem(root, "protected_ips");
    if (arr && cJSON_IsArray(arr)) {
        cJSON *item;
        cJSON_ArrayForEach(item, arr) {
            if (cJSON_IsString(item)) {
                uint32_t ip = str_to_ip(item->valuestring);
                if (ip != 0) {
                    if (ip_protected_add(ip) == 0) {
                        loaded_protected++;
                    }
                }
            }
        }
    }

    // Load protected subnets ("network/depth")
    uint32_t loaded_protected_subnets = 0;
    arr = cJSON_GetObjectItem(root, "protected_subnets");
    if (arr && cJSON_IsArray(arr)) {
        cJSON *item;
        cJSON_ArrayForEach(item, arr) {
            if (!cJSON_IsString(item)) continue;
            const char *slash = strchr(item->valuestring, '/');
            if (!slash) continue;
            char addr[32];
            size_t addr_len = (size_t)(slash - item->valuestring);
            if (addr_len == 0 || addr_len >= sizeof(addr)) continue;
            memcpy(addr, item->valuestring, addr_len);
            addr[addr_len] = '\0';
            int depth = atoi(slash + 1);
            uint32_t ip_be = str_to_ip(addr);                 // network byte order
            if (ip_be == 0 || depth < 1 || depth > 31) continue;
            if (ip_protected_subnet_add(rte_be_to_cpu_32(ip_be), (uint8_t)depth) == 0) {
                loaded_protected_subnets++;
            }
        }
    }

    // Load whitelist IPs
    arr = cJSON_GetObjectItem(root, "whitelist_ips");
    if (arr && cJSON_IsArray(arr)) {
        cJSON *item;
        cJSON_ArrayForEach(item, arr) {
            if (cJSON_IsString(item)) {
                uint32_t ip = str_to_ip(item->valuestring);
                if (ip != 0) {
                    if (ip_whitelist_add(ip, WL_MODE_BYPASS) == 0) {
                        loaded_whitelist++;
                    }
                }
            }
        }
    }

    // Load blacklist IPs
    arr = cJSON_GetObjectItem(root, "blacklist_ips");
    if (arr && cJSON_IsArray(arr)) {
        cJSON *item;
        cJSON_ArrayForEach(item, arr) {
            if (cJSON_IsString(item)) {
                uint32_t ip = str_to_ip(item->valuestring);
                if (ip != 0) {
                    if (ip_blacklist_add(ip) == 0) {
                        loaded_blacklist++;
                    }
                }
            }
        }
    }

    cJSON_Delete(root);

    RTE_LOG(INFO, IPLIST, "Loaded IP lists from %s (protected=%u, protected_subnets=%u, "
            "whitelist=%u, blacklist=%u)\n",
            path, loaded_protected, loaded_protected_subnets, loaded_whitelist, loaded_blacklist);

    return 0;
}

// ==================== Protection Profile Stubs ====================
// Full implementation requires per-IP profile storage (future work)

bool ip_protected_lookup_profile(uint32_t ip,
                                 const struct protection_profile **profile) {
    int32_t pos = -1;
    return ip_protected_lookup_profile_pos(ip, profile, &pos);
}

bool ip_protected_lookup_profile_pos(uint32_t ip,
                                     const struct protection_profile **profile,
                                     int32_t *pos) {
    // Stub: no profiles configured, treat all protected IPs as profile-less
    (void)ip;
    if (profile) *profile = NULL;
    if (pos) *pos = -1;
    return ip_protected_lookup(ip);
}

bool ip_protected_proto_rate_check(int32_t pos, uint8_t protocol,
                                   uint32_t limit_pps) {
    // Stub: no per-protocol rate tracking
    (void)pos;
    (void)protocol;
    (void)limit_pps;
    return true;  // Allow
}

uint8_t profile_proto_action(const struct protection_profile *p, uint8_t proto) {
    if (!p) return PROFILE_PROTO_ALLOW;
    (void)proto;
    return p->proto_default_action;
}

bool profile_port_allowed(const struct protection_profile *p,
                           uint8_t proto, uint16_t port) {
    if (!p) return true;
    if (proto == IPPROTO_TCP) {
        if (p->tcp_port_count == 0) return true;
        for (int i = 0; i < p->tcp_port_count; i++)
            if (p->tcp_ports[i] == port) return true;
        return false;
    }
    if (proto == IPPROTO_UDP) {
        if (p->udp_port_count == 0) return true;
        for (int i = 0; i < p->udp_port_count; i++)
            if (p->udp_ports[i] == port) return true;
        return false;
    }
    return true;
}

bool profile_other_proto_allowed(const struct protection_profile *p,
                                  uint8_t proto) {
    if (!p) return true;
    if (p->other_proto_count == 0) return true;
    for (int i = 0; i < p->other_proto_count; i++)
        if (p->other_allowed_protos[i] == proto) return true;
    return false;
}

uint32_t profile_proto_rate_limit(const struct protection_profile *p,
                                   uint8_t proto) {
    (void)p;
    (void)proto;
    return 0;  // No rate limit
}

void ip_protected_proto_counters_reset(void) {
    /* Stub: no per-protocol rate counters in stub implementation */
}

// ==================== Legitimate Sources ====================
//
// The table of sources that returned a valid SYN cookie (see ip_lists.h).
// Every packet lcore adds to it (the lcore that validates a cookie), and the
// main lcore expires entries, all without a lock. A lookup is safe on every
// lcore, but no decision makes one: syn_proxy_should_challenge() challenges a
// marked source like any other (see ip_lists.h). legitimate_ip_add() used to
// whitelist the source in bypass mode, with no expiry: Stage 5 then accepted
// all its later packets at once, so the segments of its proxied connection
// skipped Stage 9 and went out untranslated (every challenged connection
// broke), and the source skipped every protection from then on.
//
// The table is an array of 64-bit words, each one entry: the source IP
// (network byte order) in the high half and the tick its proof expires in the
// low half; 0 is an empty word. Words are read and written whole, with
// atomics: a reader sees a whole entry or none. An add and the cleanup change
// a word only by compare-and-swap, so they change it only while it holds what
// they read (legitimate_ip_clear() stores 0 into every word).
//
// The array is split into sets of LEGIT_WAYS words, one cache line each. A
// source lives only in the set its hash picks, keyed with a random value at
// init so that a sender cannot aim its sources at another source's set, and a
// lookup reads that one line. An add renews the source's own word if the set
// has one; otherwise it takes an empty or expired word, or else the word that
// expires first. When another lcore changes the chosen word first, the swap
// fails and the add looks again, twice in all; then it gives up, and the
// source is simply not marked.
//
// Expiry is in ticks of 2^legit_tick_shift TSC cycles, between 1/16 and 1/8
// of a second. A word is valid while 0 < expiry - now <= legit_ttl_ticks +
// LEGIT_CLOCK_SLACK in 32-bit wrapping arithmetic, which holds across the wrap
// of the 32-bit tick (every 8 years or more). The slack is for a reader whose
// clock lags the writer's: a cleanup pass reads the clock once and meets
// words added after the tick moved on, and lcores read their TSCs at slightly
// different moments. Without it such a word, its expiry just over the TTL
// ahead, looked like garbage, and the cleanup removed a fresh entry. A word
// further ahead is garbage; legitimate_ip_cleanup() clears it and every
// expired word, so none stays long enough to look valid after a wrap.

#define LEGIT_WAYS            8        // Words per set: one 64-byte cache line
#define LEGIT_CLEANUP_BUDGET  16384    // Words one legitimate_ip_cleanup() call examines
#define LEGIT_CLOCK_SLACK     64       // Ticks, 4 to 8 s

static uint64_t *legit_words = NULL;
static uint32_t legit_nwords = 0;        // A power of two, at least LEGIT_WAYS
static uint32_t legit_set_mask = 0;      // Number of sets - 1
static uint64_t legit_key = 0;           // Hash key, random at init
static uint32_t legit_ttl_ticks = 0;
static unsigned int legit_tick_shift = 0;
static uint32_t legit_cleanup_pos = 0;   // Where the next cleanup resumes (main lcore only)

// Test seam (see ip_lists.h): this weak default reads the TSC
__attribute__((weak)) uint64_t legitimate_ip_clock(void) {
    return rte_get_tsc_cycles();
}

// Test seam (see ip_lists.h): this weak default does nothing
__attribute__((weak)) void legitimate_ip_add_seam(void) {
}

static inline uint32_t legit_now(void) {
    return (uint32_t)(legitimate_ip_clock() >> legit_tick_shift);
}

static inline bool legit_word_valid(uint64_t w, uint32_t now) {
    return w != 0 && (uint32_t)((uint32_t)w - now - 1) < legit_ttl_ticks + LEGIT_CLOCK_SLACK;
}

// The 64-bit finalizer of MurmurHash3 (fmix64), which hyperloglog.c uses too:
// every output bit depends on every input bit, so structured addresses
// (consecutive, or differing in one byte) spread over the sets
static inline uint64_t legit_fmix64(uint64_t h) {
    h ^= h >> 33;
    h *= 0xff51afd7ed558ccdULL;
    h ^= h >> 33;
    h *= 0xc4ceb9fe1a85ec53ULL;
    h ^= h >> 33;
    return h;
}

static inline uint64_t *legit_set(uint32_t src_ip) {
    uint64_t h = legit_fmix64((uint64_t)src_ip ^ legit_key);
    return &legit_words[(size_t)((uint32_t)h & legit_set_mask) * LEGIT_WAYS];
}

int legitimate_ip_init(uint32_t table_size, uint32_t ttl_sec) {
    legitimate_ip_free();

    if (table_size == 0) table_size = LEGITIMATE_DEFAULT_TABLE_SIZE;
    if (table_size > LEGITIMATE_MAX_TABLE_SIZE) table_size = LEGITIMATE_MAX_TABLE_SIZE;
    if (table_size < LEGIT_WAYS) table_size = LEGIT_WAYS;
    if (ttl_sec == 0) ttl_sec = LEGITIMATE_DEFAULT_TTL_SEC;
    if (ttl_sec > LEGITIMATE_MAX_TTL_SEC) ttl_sec = LEGITIMATE_MAX_TTL_SEC;

    uint32_t nwords = rte_align32pow2(table_size);
    uint64_t *words = rte_zmalloc("legitimate_sources", (size_t)nwords * sizeof(uint64_t),
                                  RTE_CACHE_LINE_SIZE);
    if (!words) {
        RTE_LOG(ERR, IPLIST, "Failed to allocate the legitimate-source table (%u entries)\n",
                nwords);
        return -1;
    }

    // A tick of 2^shift cycles, 2^bits <= hz < 2^(bits + 1): 1/16 to 1/8 s
    uint64_t hz = rte_get_tsc_hz();
    unsigned int bits = hz ? 63u - (unsigned int)__builtin_clzll(hz) : 0;
    legit_tick_shift = bits > 3 ? bits - 3 : 0;
    uint64_t ticks = ((uint64_t)ttl_sec * hz + (1ull << legit_tick_shift) - 1) >> legit_tick_shift;
    legit_ttl_ticks = ticks ? (uint32_t)ticks : 1;
    legit_key = rte_rand();
    legit_set_mask = nwords / LEGIT_WAYS - 1;
    legit_cleanup_pos = 0;
    legit_nwords = nwords;
    legit_words = words;

    RTE_LOG(INFO, IPLIST, "Legitimate-source table: %u entries, TTL %u s\n", nwords, ttl_sec);
    return 0;
}

void legitimate_ip_free(void) {
    uint64_t *words = legit_words;
    legit_words = NULL;
    legit_nwords = 0;
    legit_set_mask = 0;
    legit_cleanup_pos = 0;
    if (words) {
        rte_free(words);
    }
}

void legitimate_ip_add(uint32_t src_ip) {
    if (unlikely(legit_words == NULL) || src_ip == 0) {
        return;
    }
    uint64_t *set = legit_set(src_ip);
    const uint32_t now = legit_now();
    const uint64_t want = ((uint64_t)src_ip << 32) | (uint32_t)(now + legit_ttl_ticks);

    for (int attempt = 0; attempt < 2; attempt++) {
        int pick = 0;
        uint64_t pick_word = 0;
        uint32_t pick_left = UINT32_MAX;   // Ticks the picked entry had left (0: free or expired)
        for (int i = 0; i < LEGIT_WAYS; i++) {
            uint64_t w = __atomic_load_n(&set[i], __ATOMIC_RELAXED);
            if ((uint32_t)(w >> 32) == src_ip) {
                pick = i;            // The source's own entry: renew it
                pick_word = w;
                break;
            }
            uint32_t left = legit_word_valid(w, now) ? (uint32_t)w - now : 0;
            if (left < pick_left) {
                pick = i;
                pick_word = w;
                pick_left = left;
            }
        }
        legitimate_ip_add_seam();
        if (pick_word == want ||
            __atomic_compare_exchange_n(&set[pick], &pick_word, want, false,
                                        __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
            return;
        }
        // Another lcore changed the word: look again
    }
}

bool legitimate_ip_lookup(uint32_t src_ip) {
    if (unlikely(legit_words == NULL) || src_ip == 0) {
        return false;
    }
    const uint64_t *set = legit_set(src_ip);
    for (int i = 0; i < LEGIT_WAYS; i++) {
        uint64_t w = __atomic_load_n(&set[i], __ATOMIC_RELAXED);
        // The clock is read only for a word of this source, so the SYNs of
        // other sources (a spoofed flood) cost one cache line and no TSC read
        if ((uint32_t)(w >> 32) == src_ip && legit_word_valid(w, legit_now())) {
            return true;
        }
    }
    return false;
}

uint32_t legitimate_ip_cleanup(void) {
    if (legit_words == NULL) {
        return 0;
    }
    const uint32_t now = legit_now();
    const uint32_t mask = legit_nwords - 1;
    const uint32_t budget = legit_nwords < LEGIT_CLEANUP_BUDGET ? legit_nwords : LEGIT_CLEANUP_BUDGET;
    uint32_t pos = legit_cleanup_pos;
    uint32_t removed = 0;

    for (uint32_t n = 0; n < budget; n++, pos = (pos + 1) & mask) {
        uint64_t w = __atomic_load_n(&legit_words[pos], __ATOMIC_RELAXED);
        // An add may renew the word meanwhile: the swap then fails and keeps it
        if (w != 0 && !legit_word_valid(w, now) &&
            __atomic_compare_exchange_n(&legit_words[pos], &w, 0, false,
                                        __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
            removed++;
        }
    }
    legit_cleanup_pos = pos;
    return removed;
}

uint32_t legitimate_ip_count(void) {
    if (legit_words == NULL) {
        return 0;
    }
    const uint32_t now = legit_now();
    uint32_t count = 0;
    for (uint32_t i = 0; i < legit_nwords; i++) {
        count += legit_word_valid(__atomic_load_n(&legit_words[i], __ATOMIC_RELAXED), now);
    }
    return count;
}

uint32_t legitimate_ip_capacity(void) {
    return legit_words ? legit_nwords : 0;
}

void legitimate_ip_clear(void) {
    if (legit_words == NULL) {
        return;
    }
    for (uint32_t i = 0; i < legit_nwords; i++) {
        __atomic_store_n(&legit_words[i], 0, __ATOMIC_RELAXED);
    }
}
