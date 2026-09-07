#include "policy_interface.h"
#include "types.h"
#include <rte_log.h>
#include <rte_cycles.h>
#include <rte_spinlock.h>
#include <string.h>

#define RTE_LOGTYPE_POLICY RTE_LOGTYPE_USER7

// ==================== Global State ====================

static struct layer1_shared_memory *shmem = NULL;
static uint64_t policy_hits = 0;

// Overflow tracking statistics
static uint64_t policy_overflow_count = 0;
static uint64_t policy_expired_removed = 0;

// Spinlock for policy table modifications (add/remove/update)
// Lookups are lock-free using atomic count reads
static rte_spinlock_t policy_lock = RTE_SPINLOCK_INITIALIZER;

// ==================== Helper Functions ====================

/**
 * Check if a policy matches packet features
 *
 * Wildcard matching: 0 in policy means "match any"
 */
static inline bool policy_matches(const struct policy_entry *policy,
                                  const struct packet_features *features) {
    // Check source IP (0 = wildcard)
    if (policy->src_ip != 0 && policy->src_ip != features->src_ip) {
        return false;
    }

    // Check destination IP (0 = wildcard)
    if (policy->dst_ip != 0 && policy->dst_ip != features->dst_ip) {
        return false;
    }

    // Check destination port (0 = wildcard)
    if (policy->dst_port != 0 && policy->dst_port != features->dst_port) {
        return false;
    }

    // Check protocol (0 = wildcard)
    if (policy->protocol != 0 && policy->protocol != features->protocol) {
        return false;
    }

    // Check if policy has expired
    if (policy->expiry_timestamp != 0) {
        uint64_t now = rte_get_tsc_cycles();
        if (now > policy->expiry_timestamp) {
            return false;  // Expired policy
        }
    }

    return true;  // Match!
}

// ==================== Initialization ====================

int policy_interface_init(void) {
    shmem = shared_memory_get();
    if (!shmem) {
        RTE_LOG(ERR, POLICY, "Shared memory not initialized\n");
        return -1;
    }

    rte_spinlock_init(&policy_lock);

    RTE_LOG(INFO, POLICY, "Policy interface initialized (max %d policies, thread-safe)\n",
            MAX_POLICIES);
    return 0;
}

void policy_interface_cleanup(void) {
    shmem = NULL;
    RTE_LOG(INFO, POLICY, "Policy interface cleanup complete\n");
}

// ==================== Fast Path (Layer 1) - Lock-Free ====================

void policy_lookup(const struct packet_features *features,
                   struct policy_result *result) {
    // Default: allow all traffic (fail-open behavior)
    result->matched = false;
    result->action = POLICY_ALLOW;
    result->rate_limit_pps = 0;
    result->rate_limit_bps = 0;

    if (!shmem) {
        return;  // Not initialized, allow traffic
    }

    struct policy_table *table = &shmem->policies;
    
    // Read count with acquire semantics to ensure we see all policy data
    uint32_t count = __atomic_load_n(&table->count, __ATOMIC_ACQUIRE);

    // Linear search through policies (sorted by priority)
    // This is O(N) but N is typically small (<100 active policies)
    // and policies are sorted by priority for early exit
    for (uint32_t i = 0; i < count && i < MAX_POLICIES; i++) {
        // Read the policy entry - use volatile to prevent compiler reordering
        const volatile struct policy_entry *policy = &table->entries[i];
        
        // Copy to local to avoid torn reads on multi-field check
        struct policy_entry local_policy;
        memcpy(&local_policy, (const void *)policy, sizeof(local_policy));

        if (policy_matches(&local_policy, features)) {
            // Found matching policy!
            result->matched = true;
            result->action = local_policy.action;
            result->rate_limit_pps = local_policy.rate_limit_pps;
            result->rate_limit_bps = local_policy.rate_limit_bps;

            __atomic_add_fetch(&policy_hits, 1, __ATOMIC_RELAXED);
            return;  // Return first match (highest priority)
        }
    }

    // No policy matched - default action is ALLOW
}

void policy_get_stats(uint32_t *total_policies, uint64_t *policy_hits_out) {
    if (total_policies) {
        *total_policies = shmem ? __atomic_load_n(&shmem->policies.count, __ATOMIC_RELAXED) : 0;
    }
    if (policy_hits_out) {
        *policy_hits_out = __atomic_load_n(&policy_hits, __ATOMIC_RELAXED);
    }
}

// ==================== Control Plane (Layer 3) - Locked ====================

int policy_add(const struct policy_entry *policy) {
    if (!shmem) {
        return -1;
    }

    struct policy_table *table = &shmem->policies;
    
    // Lock for modification
    rte_spinlock_lock(&policy_lock);

    uint32_t count = table->count;  // No need for atomic inside lock

    if (count >= MAX_POLICIES) {
        __atomic_add_fetch(&policy_overflow_count, 1, __ATOMIC_RELAXED);
        rte_spinlock_unlock(&policy_lock);
        RTE_LOG(ERR, POLICY, "Policy table full (%u entries), overflow #%lu\n",
                count, (unsigned long)policy_overflow_count);
        return -1;
    }

    // Copy policy to table
    memcpy(&table->entries[count], policy, sizeof(struct policy_entry));
    
    // Memory barrier to ensure policy data is visible before count update
    rte_smp_wmb();

    // Update version and count atomically (visible to lock-free readers)
    __atomic_add_fetch(&table->global_version, 1, __ATOMIC_RELEASE);
    __atomic_store_n(&table->count, count + 1, __ATOMIC_RELEASE);

    rte_spinlock_unlock(&policy_lock);

    RTE_LOG(INFO, POLICY, "Added policy: src=%u.%u.%u.%u proto=%u action=%d prio=%u\n",
            (rte_be_to_cpu_32(policy->src_ip) >> 24) & 0xFF,
            (rte_be_to_cpu_32(policy->src_ip) >> 16) & 0xFF,
            (rte_be_to_cpu_32(policy->src_ip) >> 8) & 0xFF,
            rte_be_to_cpu_32(policy->src_ip) & 0xFF,
            policy->protocol, policy->action, policy->priority);

    return 0;
}

int policy_remove(uint32_t index) {
    if (!shmem) {
        return -1;
    }

    struct policy_table *table = &shmem->policies;

    // Lock for modification
    rte_spinlock_lock(&policy_lock);

    uint32_t count = table->count;

    if (index >= count) {
        rte_spinlock_unlock(&policy_lock);
        return -1;
    }

    // Strategy: Move last entry to removed slot, then decrement count
    // This ensures readers always see valid entries
    if (index < count - 1) {
        // Copy last entry to the removed slot
        memcpy(&table->entries[index],
               &table->entries[count - 1],
               sizeof(struct policy_entry));
    }
    
    // Memory barrier before count update
    rte_smp_wmb();

    // Update version and count atomically
    __atomic_add_fetch(&table->global_version, 1, __ATOMIC_RELEASE);
    __atomic_store_n(&table->count, count - 1, __ATOMIC_RELEASE);

    rte_spinlock_unlock(&policy_lock);

    RTE_LOG(INFO, POLICY, "Removed policy at index %u\n", index);
    return 0;
}

void policy_clear_all(void) {
    if (!shmem) {
        return;
    }

    struct policy_table *table = &shmem->policies;

    rte_spinlock_lock(&policy_lock);
    
    __atomic_store_n(&table->count, 0, __ATOMIC_RELEASE);
    __atomic_add_fetch(&table->global_version, 1, __ATOMIC_RELEASE);
    
    rte_spinlock_unlock(&policy_lock);

    RTE_LOG(INFO, POLICY, "All policies cleared\n");
}

int policy_update_rate_limit(uint32_t index, uint32_t pps, uint32_t bps) {
    if (!shmem) {
        return -1;
    }

    struct policy_table *table = &shmem->policies;

    rte_spinlock_lock(&policy_lock);

    uint32_t count = table->count;

    if (index >= count) {
        rte_spinlock_unlock(&policy_lock);
        return -1;
    }

    // Update rate limits (these are read atomically by size on most architectures)
    table->entries[index].rate_limit_pps = pps;
    table->entries[index].rate_limit_bps = bps;
    
    rte_smp_wmb();
    
    __atomic_add_fetch(&table->global_version, 1, __ATOMIC_RELEASE);

    rte_spinlock_unlock(&policy_lock);

    RTE_LOG(INFO, POLICY, "Updated policy %u: pps=%u bps=%u\n", index, pps, bps);
    return 0;
}

/**
 * Insert policy at correct position based on priority (higher priority first)
 * This maintains sorted order for efficient early-exit during lookup
 */
int policy_add_sorted(const struct policy_entry *policy) {
    if (!shmem) {
        return -1;
    }

    struct policy_table *table = &shmem->policies;
    
    rte_spinlock_lock(&policy_lock);

    uint32_t count = table->count;

    if (count >= MAX_POLICIES) {
        __atomic_add_fetch(&policy_overflow_count, 1, __ATOMIC_RELAXED);
        rte_spinlock_unlock(&policy_lock);
        RTE_LOG(ERR, POLICY, "Policy table full (%u entries), overflow #%lu\n",
                count, (unsigned long)policy_overflow_count);
        return -1;
    }

    // Find insertion point (maintain descending priority order)
    uint32_t insert_pos = count;
    for (uint32_t i = 0; i < count; i++) {
        if (policy->priority > table->entries[i].priority) {
            insert_pos = i;
            break;
        }
    }

    // Shift entries down to make room
    if (insert_pos < count) {
        memmove(&table->entries[insert_pos + 1],
                &table->entries[insert_pos],
                (count - insert_pos) * sizeof(struct policy_entry));
    }

    // Insert new policy
    memcpy(&table->entries[insert_pos], policy, sizeof(struct policy_entry));
    
    rte_smp_wmb();

    __atomic_add_fetch(&table->global_version, 1, __ATOMIC_RELEASE);
    __atomic_store_n(&table->count, count + 1, __ATOMIC_RELEASE);

    rte_spinlock_unlock(&policy_lock);

    RTE_LOG(INFO, POLICY, "Added policy at position %u (priority %u)\n",
            insert_pos, policy->priority);

    return 0;
}

// ==================== Overflow Handling ====================

uint32_t policy_cleanup_expired(void) {
    if (!shmem) {
        return 0;
    }

    struct policy_table *table = &shmem->policies;
    uint64_t now_ns = rte_get_tsc_cycles() * 1000000000ULL / rte_get_tsc_hz();
    uint32_t removed = 0;

    rte_spinlock_lock(&policy_lock);

    uint32_t count = table->count;
    uint32_t write_idx = 0;

    // Compact the table, removing expired entries
    for (uint32_t read_idx = 0; read_idx < count; read_idx++) {
        struct policy_entry *entry = &table->entries[read_idx];

        // Check if expired (0 means no expiry)
        if (entry->expiry_timestamp != 0 && entry->expiry_timestamp < now_ns) {
            // Entry expired, skip it (don't copy to write position)
            removed++;
            continue;
        }

        // Entry still valid, move to compacted position if needed
        if (write_idx != read_idx) {
            memcpy(&table->entries[write_idx], entry, sizeof(struct policy_entry));
        }
        write_idx++;
    }

    if (removed > 0) {
        // Update count and version
        rte_smp_wmb();
        __atomic_add_fetch(&table->global_version, 1, __ATOMIC_RELEASE);
        __atomic_store_n(&table->count, write_idx, __ATOMIC_RELEASE);

        __atomic_add_fetch(&policy_expired_removed, removed, __ATOMIC_RELAXED);

        RTE_LOG(INFO, POLICY, "Cleaned up %u expired policies, %u remaining\n",
                removed, write_idx);
    }

    rte_spinlock_unlock(&policy_lock);

    return removed;
}

void policy_get_overflow_stats(uint64_t *overflow_count, uint64_t *expired_removed) {
    if (overflow_count) {
        *overflow_count = __atomic_load_n(&policy_overflow_count, __ATOMIC_RELAXED);
    }
    if (expired_removed) {
        *expired_removed = __atomic_load_n(&policy_expired_removed, __ATOMIC_RELAXED);
    }
}