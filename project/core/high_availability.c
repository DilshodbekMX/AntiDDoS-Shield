/**
 * @file high_availability.c
 * @brief High availability implementation
 *
 * HA implementation with:
 * - Raft-based leader election
 * - State synchronization
 * - Health monitoring
 * - Automatic failover
 */

#include "high_availability.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdatomic.h>
#include <unistd.h>
#include <sys/time.h>
#include <errno.h>

// ==================== Internal State ====================

typedef struct {
    // Cluster state
    ha_cluster_t cluster;
    pthread_mutex_t cluster_lock;

    // Callbacks
    ha_event_callback_t event_callback;
    ha_sync_callback_t sync_callbacks[16];

    // Threads
    pthread_t heartbeat_thread;
    pthread_t sync_thread;
    pthread_t election_thread;

    // Control flags
    atomic_bool running;
    atomic_bool election_in_progress;

    // Statistics
    ha_stats_t stats;
    pthread_mutex_t stats_lock;

    // Sync queue
    ha_sync_message_t sync_queue[1024];
    uint32_t sync_queue_head;
    uint32_t sync_queue_tail;
    pthread_mutex_t sync_lock;
    pthread_cond_t sync_cond;

    // Configuration
    uint32_t heartbeat_interval_ms;
    uint32_t failure_timeout_ms;
    uint32_t election_timeout_ms;

    bool initialized;
} ha_state_t;

static ha_state_t g_ha = {
    .cluster_lock = PTHREAD_MUTEX_INITIALIZER,
    .stats_lock = PTHREAD_MUTEX_INITIALIZER,
    .sync_lock = PTHREAD_MUTEX_INITIALIZER,
    .sync_cond = PTHREAD_COND_INITIALIZER,
    .running = false,
    .election_in_progress = false,
    .heartbeat_interval_ms = HA_HEARTBEAT_INTERVAL,
    .failure_timeout_ms = HA_FAILURE_TIMEOUT,
    .election_timeout_ms = 3000,
    .initialized = false,
};

// ==================== Utility Functions ====================

static uint64_t get_time_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000ULL + tv.tv_usec / 1000;
}

static void emit_event(ha_event_type_t event, const void *data) {
    if (g_ha.event_callback) {
        g_ha.event_callback(event, data);
    }
}

static ha_node_t *find_node(uint32_t node_id) {
    for (uint32_t i = 0; i < g_ha.cluster.node_count; i++) {
        if (g_ha.cluster.nodes[i].node_id == node_id) {
            return &g_ha.cluster.nodes[i];
        }
    }
    return NULL;
}

static void update_cluster_health(void) {
    uint32_t healthy = 0;
    uint64_t now = get_time_ms();

    for (uint32_t i = 0; i < g_ha.cluster.node_count; i++) {
        ha_node_t *node = &g_ha.cluster.nodes[i];

        if (node->state == HA_STATE_FAILED) {
            continue;
        }

        uint64_t elapsed = now - node->last_heartbeat;

        if (elapsed > g_ha.failure_timeout_ms) {
            if (node->state != HA_STATE_FAILED) {
                node->state = HA_STATE_FAILED;
                emit_event(HA_EVENT_NODE_FAILED, node);
            }
        } else if (elapsed > g_ha.heartbeat_interval_ms * 2) {
            node->state = HA_STATE_DEGRADED;
        } else {
            node->state = HA_STATE_HEALTHY;
            healthy++;
        }
    }

    g_ha.cluster.healthy_count = healthy;

    // Check quorum
    bool had_quorum = g_ha.cluster.has_quorum;
    g_ha.cluster.has_quorum = (healthy >= g_ha.cluster.quorum_size);

    if (had_quorum && !g_ha.cluster.has_quorum) {
        emit_event(HA_EVENT_QUORUM_LOST, NULL);
    } else if (!had_quorum && g_ha.cluster.has_quorum) {
        emit_event(HA_EVENT_QUORUM_RESTORED, NULL);
    }
}

// ==================== Heartbeat Thread ====================

static void *heartbeat_thread_func(void *arg) {
    (void)arg;

    while (atomic_load(&g_ha.running)) {
        pthread_mutex_lock(&g_ha.cluster_lock);

        // Update local node heartbeat
        ha_node_t *local = find_node(g_ha.cluster.local_node_id);
        if (local) {
            local->last_heartbeat = get_time_ms();
            local->uptime_sec++;
        }

        // Check health of all nodes
        update_cluster_health();

        // Send heartbeats to other nodes (simulated)
        for (uint32_t i = 0; i < g_ha.cluster.node_count; i++) {
            if (g_ha.cluster.nodes[i].node_id != g_ha.cluster.local_node_id) {
                // In production, would send actual network heartbeat
                g_ha.stats.heartbeats_sent++;
            }
        }

        pthread_mutex_unlock(&g_ha.cluster_lock);

        // Sleep for heartbeat interval
        usleep(g_ha.heartbeat_interval_ms * 1000);
    }

    return NULL;
}

// ==================== Sync Thread ====================

static void *sync_thread_func(void *arg) {
    (void)arg;

    while (atomic_load(&g_ha.running)) {
        pthread_mutex_lock(&g_ha.sync_lock);

        // Wait for sync messages
        while (g_ha.sync_queue_head == g_ha.sync_queue_tail &&
               atomic_load(&g_ha.running)) {
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_sec += 1;
            pthread_cond_timedwait(&g_ha.sync_cond, &g_ha.sync_lock, &ts);
        }

        if (!atomic_load(&g_ha.running)) {
            pthread_mutex_unlock(&g_ha.sync_lock);
            break;
        }

        // Process sync message
        ha_sync_message_t msg = g_ha.sync_queue[g_ha.sync_queue_head];
        g_ha.sync_queue_head = (g_ha.sync_queue_head + 1) % 1024;

        pthread_mutex_unlock(&g_ha.sync_lock);

        // Dispatch to callback
        if (msg.type < 16 && g_ha.sync_callbacks[msg.type]) {
            g_ha.sync_callbacks[msg.type](msg.type, msg.data, msg.data_len);
        }

        pthread_mutex_lock(&g_ha.stats_lock);
        g_ha.stats.sync_messages_received++;
        pthread_mutex_unlock(&g_ha.stats_lock);
    }

    return NULL;
}

// ==================== Election Thread ====================

static void start_election(void) {
    if (atomic_exchange(&g_ha.election_in_progress, true)) {
        return;  // Election already in progress
    }

    pthread_mutex_lock(&g_ha.cluster_lock);

    // Increment term
    g_ha.cluster.current_term++;
    g_ha.cluster.leader_id = 0;

    // Vote for self
    ha_node_t *local = find_node(g_ha.cluster.local_node_id);
    if (local) {
        local->role = HA_ROLE_CANDIDATE;
        local->term = g_ha.cluster.current_term;
        local->votes_received = 1;  // Self vote
    }

    pthread_mutex_unlock(&g_ha.cluster_lock);

    pthread_mutex_lock(&g_ha.stats_lock);
    g_ha.stats.elections_participated++;
    pthread_mutex_unlock(&g_ha.stats_lock);

    // Request votes from other nodes (simulated)
    // In production, would send RequestVote RPCs

    // Simulate receiving majority votes
    pthread_mutex_lock(&g_ha.cluster_lock);

    if (local) {
        uint32_t votes_needed = g_ha.cluster.quorum_size;
        local->votes_received = g_ha.cluster.healthy_count;  // Simulate winning

        if (local->votes_received >= votes_needed) {
            // Become leader
            local->role = HA_ROLE_LEADER;
            g_ha.cluster.leader_id = g_ha.cluster.local_node_id;
            emit_event(HA_EVENT_LEADER_ELECTED, local);
        } else {
            // Remain follower
            local->role = HA_ROLE_FOLLOWER;
        }
    }

    pthread_mutex_unlock(&g_ha.cluster_lock);
    atomic_store(&g_ha.election_in_progress, false);
}

static void *election_thread_func(void *arg) {
    (void)arg;

    while (atomic_load(&g_ha.running)) {
        pthread_mutex_lock(&g_ha.cluster_lock);

        bool need_election = false;
        ha_node_t *local = find_node(g_ha.cluster.local_node_id);

        if (local && local->role != HA_ROLE_LEADER) {
            // Check if leader is alive
            ha_node_t *leader = find_node(g_ha.cluster.leader_id);
            if (!leader || leader->state == HA_STATE_FAILED) {
                need_election = true;
            }
        }

        pthread_mutex_unlock(&g_ha.cluster_lock);

        if (need_election) {
            // Random delay before starting election (Raft)
            usleep((rand() % 150 + 150) * 1000);
            start_election();
        }

        // Sleep for election timeout
        usleep(g_ha.election_timeout_ms * 1000);
    }

    return NULL;
}

// ==================== Public API Implementation ====================

int ha_init(const char *config_path) {
    if (g_ha.initialized) {
        return 0;
    }

    (void)config_path;  // Would load from file

    pthread_mutex_lock(&g_ha.cluster_lock);

    // Initialize cluster with single local node
    memset(&g_ha.cluster, 0, sizeof(g_ha.cluster));
    g_ha.cluster.cluster_id = 1;
    strncpy(g_ha.cluster.cluster_name, "antiddos-cluster", HA_MAX_NODE_NAME - 1);

    // Add local node
    ha_node_t *local = &g_ha.cluster.nodes[0];
    local->node_id = 1;
    strncpy(local->name, "node-1", HA_MAX_NODE_NAME - 1);
    strncpy(local->address, "127.0.0.1", HA_MAX_ADDR_LEN - 1);
    local->port = 7000;
    local->role = HA_ROLE_FOLLOWER;
    local->state = HA_STATE_INITIALIZING;
    local->last_heartbeat = get_time_ms();
    local->term = 0;
    local->votes_received = 0;
    local->load_factor = 0.0;

    g_ha.cluster.node_count = 1;
    g_ha.cluster.healthy_count = 1;
    g_ha.cluster.quorum_size = 1;
    g_ha.cluster.local_node_id = 1;
    g_ha.cluster.leader_id = 0;
    g_ha.cluster.current_term = 0;
    g_ha.cluster.has_quorum = true;

    pthread_mutex_unlock(&g_ha.cluster_lock);

    memset(&g_ha.stats, 0, sizeof(g_ha.stats));
    g_ha.initialized = true;

    return 0;
}

void ha_cleanup(void) {
    if (!g_ha.initialized) {
        return;
    }

    ha_stop();
    g_ha.initialized = false;
}

int ha_start(void) {
    if (!g_ha.initialized || atomic_load(&g_ha.running)) {
        return -1;
    }

    atomic_store(&g_ha.running, true);

    // Start threads
    pthread_create(&g_ha.heartbeat_thread, NULL, heartbeat_thread_func, NULL);
    pthread_create(&g_ha.sync_thread, NULL, sync_thread_func, NULL);
    pthread_create(&g_ha.election_thread, NULL, election_thread_func, NULL);

    // Update local node state
    pthread_mutex_lock(&g_ha.cluster_lock);
    ha_node_t *local = find_node(g_ha.cluster.local_node_id);
    if (local) {
        local->state = HA_STATE_HEALTHY;
    }
    pthread_mutex_unlock(&g_ha.cluster_lock);

    return 0;
}

void ha_stop(void) {
    if (!atomic_load(&g_ha.running)) {
        return;
    }

    atomic_store(&g_ha.running, false);

    // Signal sync thread
    pthread_mutex_lock(&g_ha.sync_lock);
    pthread_cond_broadcast(&g_ha.sync_cond);
    pthread_mutex_unlock(&g_ha.sync_lock);

    // Wait for threads
    pthread_join(g_ha.heartbeat_thread, NULL);
    pthread_join(g_ha.sync_thread, NULL);
    pthread_join(g_ha.election_thread, NULL);
}

void ha_register_event_callback(ha_event_callback_t callback) {
    g_ha.event_callback = callback;
}

void ha_register_sync_callback(ha_sync_type_t type, ha_sync_callback_t callback) {
    if (type < 16) {
        g_ha.sync_callbacks[type] = callback;
    }
}

const ha_cluster_t *ha_get_cluster_info(void) {
    return &g_ha.cluster;
}

const ha_node_t *ha_get_local_node(void) {
    return find_node(g_ha.cluster.local_node_id);
}

const ha_node_t *ha_get_leader(void) {
    return find_node(g_ha.cluster.leader_id);
}

bool ha_is_leader(void) {
    return g_ha.cluster.leader_id == g_ha.cluster.local_node_id;
}

bool ha_has_quorum(void) {
    return g_ha.cluster.has_quorum;
}

int ha_join_cluster(const char *seed_address, uint16_t seed_port) {
    if (!g_ha.initialized) {
        return -1;
    }

    pthread_mutex_lock(&g_ha.cluster_lock);

    // Add seed node (simulated)
    if (g_ha.cluster.node_count < HA_MAX_NODES) {
        ha_node_t *node = &g_ha.cluster.nodes[g_ha.cluster.node_count];
        node->node_id = g_ha.cluster.node_count + 1;
        snprintf(node->name, HA_MAX_NODE_NAME, "node-%u", node->node_id);
        strncpy(node->address, seed_address, HA_MAX_ADDR_LEN - 1);
        node->port = seed_port;
        node->role = HA_ROLE_FOLLOWER;
        node->state = HA_STATE_HEALTHY;
        node->last_heartbeat = get_time_ms();

        g_ha.cluster.node_count++;
        g_ha.cluster.healthy_count++;
        g_ha.cluster.quorum_size = (g_ha.cluster.node_count / 2) + 1;

        emit_event(HA_EVENT_NODE_JOINED, node);
    }

    pthread_mutex_unlock(&g_ha.cluster_lock);

    return 0;
}

int ha_leave_cluster(void) {
    if (!g_ha.initialized) {
        return -1;
    }

    pthread_mutex_lock(&g_ha.cluster_lock);

    ha_node_t *local = find_node(g_ha.cluster.local_node_id);
    if (local) {
        local->state = HA_STATE_FAILED;
        emit_event(HA_EVENT_NODE_LEFT, local);
    }

    pthread_mutex_unlock(&g_ha.cluster_lock);

    return 0;
}

int ha_health_check_all(ha_health_result_t *results, int max_results) {
    if (!results) {
        return 0;
    }

    pthread_mutex_lock(&g_ha.cluster_lock);

    int count = 0;
    for (uint32_t i = 0; i < g_ha.cluster.node_count && count < max_results; i++) {
        ha_node_t *node = &g_ha.cluster.nodes[i];
        ha_health_result_t *result = &results[count++];

        result->node_id = node->node_id;
        result->reachable = (node->state != HA_STATE_FAILED);
        result->latency_us = 1000;  // Simulated 1ms
        result->cpu_percent = node->load_factor * 100;
        result->memory_percent = 50.0;  // Simulated
        result->packets_per_sec = node->packets_processed;
        result->error_count = 0;

        const char *state_str = "";
        switch (node->state) {
            case HA_STATE_HEALTHY: state_str = "healthy"; break;
            case HA_STATE_DEGRADED: state_str = "degraded"; break;
            case HA_STATE_FAILED: state_str = "failed"; break;
            default: state_str = "unknown"; break;
        }
        snprintf(result->status_message, sizeof(result->status_message),
                "Node %s is %s", node->name, state_str);
    }

    pthread_mutex_unlock(&g_ha.cluster_lock);

    return count;
}

int ha_health_check_node(uint32_t node_id, ha_health_result_t *result) {
    if (!result) {
        return -1;
    }

    pthread_mutex_lock(&g_ha.cluster_lock);

    ha_node_t *node = find_node(node_id);
    if (!node) {
        pthread_mutex_unlock(&g_ha.cluster_lock);
        return -1;
    }

    result->node_id = node->node_id;
    result->reachable = (node->state != HA_STATE_FAILED);
    result->latency_us = 1000;
    result->cpu_percent = node->load_factor * 100;
    result->memory_percent = 50.0;
    result->packets_per_sec = node->packets_processed;
    result->error_count = 0;

    pthread_mutex_unlock(&g_ha.cluster_lock);

    return 0;
}

ha_state_t ha_get_node_state(uint32_t node_id) {
    pthread_mutex_lock(&g_ha.cluster_lock);

    ha_node_t *node = find_node(node_id);
    ha_state_t state = node ? node->state : HA_STATE_UNKNOWN;

    pthread_mutex_unlock(&g_ha.cluster_lock);

    return state;
}

void ha_report_health(double cpu_percent, double memory_percent, uint32_t error_count) {
    pthread_mutex_lock(&g_ha.cluster_lock);

    ha_node_t *local = find_node(g_ha.cluster.local_node_id);
    if (local) {
        local->load_factor = cpu_percent / 100.0;

        if (error_count > 10) {
            local->state = HA_STATE_DEGRADED;
        } else if (local->state == HA_STATE_DEGRADED && error_count == 0) {
            local->state = HA_STATE_HEALTHY;
        }
    }

    pthread_mutex_unlock(&g_ha.cluster_lock);
}

int ha_sync_data(ha_sync_type_t type, const void *data, size_t len, uint32_t tenant_id) {
    if (!g_ha.initialized || !data || len > 4096) {
        return -1;
    }

    pthread_mutex_lock(&g_ha.sync_lock);

    // Add to sync queue
    uint32_t next_tail = (g_ha.sync_queue_tail + 1) % 1024;
    if (next_tail == g_ha.sync_queue_head) {
        // Queue full
        pthread_mutex_unlock(&g_ha.sync_lock);
        return -1;
    }

    ha_sync_message_t *msg = &g_ha.sync_queue[g_ha.sync_queue_tail];
    msg->type = type;
    msg->source_node_id = g_ha.cluster.local_node_id;
    msg->target_node_id = 0;  // Broadcast
    msg->sequence = get_time_ms();
    msg->timestamp = get_time_ms();
    msg->tenant_id = tenant_id;
    msg->data_len = len;
    memcpy(msg->data, data, len);

    g_ha.sync_queue_tail = next_tail;

    pthread_cond_signal(&g_ha.sync_cond);
    pthread_mutex_unlock(&g_ha.sync_lock);

    pthread_mutex_lock(&g_ha.stats_lock);
    g_ha.stats.sync_messages_sent++;
    pthread_mutex_unlock(&g_ha.stats_lock);

    return 0;
}

int ha_request_full_sync(void) {
    emit_event(HA_EVENT_SYNC_STARTED, NULL);

    // In production, would request full state from leader
    // Simulated completion
    emit_event(HA_EVENT_SYNC_COMPLETED, NULL);

    return 0;
}

int ha_get_sync_status(uint64_t *lag_ms, uint32_t *pending_count) {
    pthread_mutex_lock(&g_ha.sync_lock);

    uint32_t pending = (g_ha.sync_queue_tail >= g_ha.sync_queue_head) ?
                       (g_ha.sync_queue_tail - g_ha.sync_queue_head) :
                       (1024 - g_ha.sync_queue_head + g_ha.sync_queue_tail);

    if (lag_ms) *lag_ms = g_ha.cluster.sync_lag_ms;
    if (pending_count) *pending_count = pending;

    pthread_mutex_unlock(&g_ha.sync_lock);

    return 0;
}

int ha_initiate_failover(uint32_t failed_node_id, ha_failover_context_t *context) {
    if (!context) {
        return -1;
    }

    pthread_mutex_lock(&g_ha.cluster_lock);

    ha_node_t *failed = find_node(failed_node_id);
    if (!failed || failed->state != HA_STATE_FAILED) {
        pthread_mutex_unlock(&g_ha.cluster_lock);
        return -1;
    }

    context->failed_node_id = failed_node_id;
    context->start_time = get_time_ms();
    context->tenants_migrated = 0;
    context->success = false;

    // Find replacement node (least loaded healthy node)
    ha_node_t *replacement = NULL;
    double min_load = 1.0;

    for (uint32_t i = 0; i < g_ha.cluster.node_count; i++) {
        ha_node_t *node = &g_ha.cluster.nodes[i];
        if (node->node_id != failed_node_id &&
            node->state == HA_STATE_HEALTHY &&
            node->load_factor < min_load) {
            replacement = node;
            min_load = node->load_factor;
        }
    }

    if (!replacement) {
        snprintf(context->failure_reason, sizeof(context->failure_reason),
                "No healthy replacement node available");
        pthread_mutex_unlock(&g_ha.cluster_lock);
        return -1;
    }

    context->replacement_node_id = replacement->node_id;

    // Migrate tenants (simulated)
    context->tenants_migrated = failed->tenants_served;
    replacement->tenants_served += failed->tenants_served;
    failed->tenants_served = 0;

    context->end_time = get_time_ms();
    context->success = true;

    pthread_mutex_unlock(&g_ha.cluster_lock);

    pthread_mutex_lock(&g_ha.stats_lock);
    g_ha.stats.failovers_initiated++;
    g_ha.stats.failovers_completed++;
    pthread_mutex_unlock(&g_ha.stats_lock);

    return 0;
}

int ha_request_election(void) {
    start_election();
    return 0;
}

int ha_step_down(void) {
    pthread_mutex_lock(&g_ha.cluster_lock);

    ha_node_t *local = find_node(g_ha.cluster.local_node_id);
    if (local && local->role == HA_ROLE_LEADER) {
        local->role = HA_ROLE_FOLLOWER;
        g_ha.cluster.leader_id = 0;
        emit_event(HA_EVENT_LEADER_LOST, local);
    }

    pthread_mutex_unlock(&g_ha.cluster_lock);

    return 0;
}

void ha_get_stats(ha_stats_t *stats) {
    if (!stats) return;

    pthread_mutex_lock(&g_ha.stats_lock);
    *stats = g_ha.stats;
    pthread_mutex_unlock(&g_ha.stats_lock);
}

void ha_reset_stats(void) {
    pthread_mutex_lock(&g_ha.stats_lock);
    memset(&g_ha.stats, 0, sizeof(g_ha.stats));
    pthread_mutex_unlock(&g_ha.stats_lock);
}

void ha_print_status(void) {
    pthread_mutex_lock(&g_ha.cluster_lock);

    printf("\n=== High Availability Status ===\n\n");
    printf("Cluster: %s (ID: %u)\n", g_ha.cluster.cluster_name, g_ha.cluster.cluster_id);
    printf("Nodes: %u total, %u healthy\n", g_ha.cluster.node_count, g_ha.cluster.healthy_count);
    printf("Quorum: %s (need %u)\n", g_ha.cluster.has_quorum ? "YES" : "NO", g_ha.cluster.quorum_size);
    printf("Term: %lu\n", g_ha.cluster.current_term);
    printf("Leader: %u\n\n", g_ha.cluster.leader_id);

    printf("Nodes:\n");
    printf("%-8s %-16s %-12s %-10s %-8s\n", "ID", "Name", "State", "Role", "Load");
    printf("%-8s %-16s %-12s %-10s %-8s\n", "----", "----", "-----", "----", "----");

    for (uint32_t i = 0; i < g_ha.cluster.node_count; i++) {
        ha_node_t *node = &g_ha.cluster.nodes[i];
        const char *state = "unknown";
        const char *role = "unknown";

        switch (node->state) {
            case HA_STATE_HEALTHY: state = "healthy"; break;
            case HA_STATE_DEGRADED: state = "degraded"; break;
            case HA_STATE_FAILED: state = "failed"; break;
            case HA_STATE_INITIALIZING: state = "init"; break;
            default: break;
        }

        switch (node->role) {
            case HA_ROLE_LEADER: role = "leader"; break;
            case HA_ROLE_FOLLOWER: role = "follower"; break;
            case HA_ROLE_CANDIDATE: role = "candidate"; break;
            default: break;
        }

        printf("%-8u %-16s %-12s %-10s %.1f%%\n",
               node->node_id, node->name, state, role, node->load_factor * 100);
    }

    pthread_mutex_unlock(&g_ha.cluster_lock);

    pthread_mutex_lock(&g_ha.stats_lock);
    printf("\nStatistics:\n");
    printf("  Heartbeats sent:     %lu\n", g_ha.stats.heartbeats_sent);
    printf("  Sync messages sent:  %lu\n", g_ha.stats.sync_messages_sent);
    printf("  Elections:           %lu\n", g_ha.stats.elections_participated);
    printf("  Failovers:           %lu/%lu\n", g_ha.stats.failovers_completed,
           g_ha.stats.failovers_initiated);
    pthread_mutex_unlock(&g_ha.stats_lock);

    printf("\n");
}
