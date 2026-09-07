/**
 * @file high_availability.h
 * @brief High availability module for multi-tenant Anti-DDoS system
 *
 * HA features:
 * - State synchronization between nodes
 * - Health checks and heartbeats
 * - Automatic failover
 * - Distributed consensus
 */

#ifndef HIGH_AVAILABILITY_H
#define HIGH_AVAILABILITY_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <time.h>

// ==================== Constants ====================

#define HA_MAX_NODES            16
#define HA_MAX_NODE_NAME        64
#define HA_MAX_ADDR_LEN         256
#define HA_HEARTBEAT_INTERVAL   1000    // ms
#define HA_FAILURE_TIMEOUT      5000    // ms
#define HA_SYNC_BATCH_SIZE      100

// Node roles
typedef enum {
    HA_ROLE_UNKNOWN = 0,
    HA_ROLE_LEADER,
    HA_ROLE_FOLLOWER,
    HA_ROLE_CANDIDATE,
    HA_ROLE_OBSERVER,
} ha_role_t;

// Node states
typedef enum {
    HA_STATE_UNKNOWN = 0,
    HA_STATE_INITIALIZING,
    HA_STATE_HEALTHY,
    HA_STATE_DEGRADED,
    HA_STATE_FAILING,
    HA_STATE_FAILED,
    HA_STATE_RECOVERING,
} ha_state_t;

// Sync types
typedef enum {
    HA_SYNC_FULL = 0,
    HA_SYNC_INCREMENTAL,
    HA_SYNC_TENANT_CONFIG,
    HA_SYNC_BLACKLIST,
    HA_SYNC_WHITELIST,
    HA_SYNC_ATTACK_STATE,
    HA_SYNC_STATS,
} ha_sync_type_t;

// Event types
typedef enum {
    HA_EVENT_NODE_JOINED = 0,
    HA_EVENT_NODE_LEFT,
    HA_EVENT_NODE_FAILED,
    HA_EVENT_NODE_RECOVERED,
    HA_EVENT_LEADER_ELECTED,
    HA_EVENT_LEADER_LOST,
    HA_EVENT_SYNC_STARTED,
    HA_EVENT_SYNC_COMPLETED,
    HA_EVENT_SPLIT_BRAIN,
    HA_EVENT_QUORUM_LOST,
    HA_EVENT_QUORUM_RESTORED,
} ha_event_type_t;

// ==================== Data Structures ====================

/**
 * @brief Node information
 */
typedef struct {
    uint32_t node_id;
    char name[HA_MAX_NODE_NAME];
    char address[HA_MAX_ADDR_LEN];
    uint16_t port;
    ha_role_t role;
    ha_state_t state;
    uint64_t last_heartbeat;            // Timestamp in ms
    uint64_t term;                      // Raft term
    uint32_t votes_received;            // For leader election
    double load_factor;                 // Current load (0.0-1.0)
    uint32_t tenants_served;            // Number of tenants
    uint64_t packets_processed;         // Total packets
    uint64_t uptime_sec;                // Uptime in seconds
} ha_node_t;

/**
 * @brief Cluster information
 */
typedef struct {
    uint32_t cluster_id;
    char cluster_name[HA_MAX_NODE_NAME];
    ha_node_t nodes[HA_MAX_NODES];
    uint32_t node_count;
    uint32_t healthy_count;
    uint32_t quorum_size;
    uint32_t local_node_id;
    uint32_t leader_id;
    uint64_t current_term;
    bool has_quorum;
    bool split_brain_detected;
    uint64_t last_sync_time;
    uint64_t sync_lag_ms;
} ha_cluster_t;

/**
 * @brief Sync message
 */
typedef struct {
    ha_sync_type_t type;
    uint32_t source_node_id;
    uint32_t target_node_id;            // 0 for broadcast
    uint64_t sequence;
    uint64_t timestamp;
    uint32_t tenant_id;                 // For tenant-specific sync
    uint32_t data_len;
    uint8_t data[4096];                 // Sync data payload
} ha_sync_message_t;

/**
 * @brief Health check result
 */
typedef struct {
    uint32_t node_id;
    bool reachable;
    uint64_t latency_us;
    double cpu_percent;
    double memory_percent;
    uint64_t packets_per_sec;
    uint32_t error_count;
    char status_message[256];
} ha_health_result_t;

/**
 * @brief Failover context
 */
typedef struct {
    uint32_t failed_node_id;
    uint32_t replacement_node_id;
    uint32_t tenants_migrated;
    uint64_t start_time;
    uint64_t end_time;
    bool success;
    char failure_reason[256];
} ha_failover_context_t;

// ==================== Callbacks ====================

/**
 * @brief Event callback type
 */
typedef void (*ha_event_callback_t)(ha_event_type_t event, const void *data);

/**
 * @brief Sync data callback type
 */
typedef int (*ha_sync_callback_t)(ha_sync_type_t type, const void *data, size_t len);

// ==================== Initialization API ====================

/**
 * @brief Initialize HA subsystem
 * @param config_path Path to HA configuration file
 * @return 0 on success
 */
int ha_init(const char *config_path);

/**
 * @brief Cleanup HA subsystem
 */
void ha_cleanup(void);

/**
 * @brief Start HA services
 * @return 0 on success
 */
int ha_start(void);

/**
 * @brief Stop HA services
 */
void ha_stop(void);

/**
 * @brief Register event callback
 * @param callback Event callback function
 */
void ha_register_event_callback(ha_event_callback_t callback);

/**
 * @brief Register sync callback for data type
 * @param type Sync type
 * @param callback Sync callback function
 */
void ha_register_sync_callback(ha_sync_type_t type, ha_sync_callback_t callback);

// ==================== Cluster Management API ====================

/**
 * @brief Get cluster information
 * @return Pointer to cluster info (read-only)
 */
const ha_cluster_t *ha_get_cluster_info(void);

/**
 * @brief Get local node information
 * @return Pointer to local node info (read-only)
 */
const ha_node_t *ha_get_local_node(void);

/**
 * @brief Get leader node
 * @return Pointer to leader node, NULL if no leader
 */
const ha_node_t *ha_get_leader(void);

/**
 * @brief Check if local node is leader
 * @return true if leader
 */
bool ha_is_leader(void);

/**
 * @brief Check if cluster has quorum
 * @return true if quorum
 */
bool ha_has_quorum(void);

/**
 * @brief Join cluster
 * @param seed_address Address of seed node
 * @param seed_port Port of seed node
 * @return 0 on success
 */
int ha_join_cluster(const char *seed_address, uint16_t seed_port);

/**
 * @brief Leave cluster gracefully
 * @return 0 on success
 */
int ha_leave_cluster(void);

// ==================== Health Check API ====================

/**
 * @brief Perform health check on all nodes
 * @param results Output array for results
 * @param max_results Maximum results
 * @return Number of results
 */
int ha_health_check_all(ha_health_result_t *results, int max_results);

/**
 * @brief Perform health check on specific node
 * @param node_id Node identifier
 * @param result Output health result
 * @return 0 on success
 */
int ha_health_check_node(uint32_t node_id, ha_health_result_t *result);

/**
 * @brief Get node health status
 * @param node_id Node identifier
 * @return Node state
 */
ha_state_t ha_get_node_state(uint32_t node_id);

/**
 * @brief Report local health status
 * @param cpu_percent CPU usage
 * @param memory_percent Memory usage
 * @param error_count Error count
 */
void ha_report_health(double cpu_percent, double memory_percent, uint32_t error_count);

// ==================== State Synchronization API ====================

/**
 * @brief Synchronize data to cluster
 * @param type Sync type
 * @param data Data to sync
 * @param len Data length
 * @param tenant_id Tenant ID (0 for global)
 * @return 0 on success
 */
int ha_sync_data(ha_sync_type_t type, const void *data, size_t len, uint32_t tenant_id);

/**
 * @brief Request full sync from leader
 * @return 0 on success
 */
int ha_request_full_sync(void);

/**
 * @brief Get sync status
 * @param lag_ms Output sync lag in milliseconds
 * @param pending_count Output pending sync messages
 * @return 0 on success
 */
int ha_get_sync_status(uint64_t *lag_ms, uint32_t *pending_count);

/**
 * @brief Force sync to specific node
 * @param node_id Target node
 * @return 0 on success
 */
int ha_force_sync_to_node(uint32_t node_id);

// ==================== Failover API ====================

/**
 * @brief Initiate failover from failed node
 * @param failed_node_id Failed node ID
 * @param context Failover context output
 * @return 0 on success
 */
int ha_initiate_failover(uint32_t failed_node_id, ha_failover_context_t *context);

/**
 * @brief Get failover status
 * @param context Failover context
 * @return 0 if complete, 1 if in progress, -1 on error
 */
int ha_get_failover_status(ha_failover_context_t *context);

/**
 * @brief Migrate tenant to different node
 * @param tenant_id Tenant ID
 * @param target_node_id Target node
 * @return 0 on success
 */
int ha_migrate_tenant(uint32_t tenant_id, uint32_t target_node_id);

/**
 * @brief Rebalance tenants across nodes
 * @return Number of tenants moved
 */
int ha_rebalance_tenants(void);

// ==================== Leader Election API ====================

/**
 * @brief Request leader election
 * @return 0 on success
 */
int ha_request_election(void);

/**
 * @brief Step down as leader
 * @return 0 on success
 */
int ha_step_down(void);

/**
 * @brief Vote for candidate
 * @param candidate_id Candidate node ID
 * @param term Election term
 * @return 0 on success
 */
int ha_vote_for(uint32_t candidate_id, uint64_t term);

// ==================== Monitoring API ====================

/**
 * @brief HA statistics
 */
typedef struct {
    uint64_t heartbeats_sent;
    uint64_t heartbeats_received;
    uint64_t sync_messages_sent;
    uint64_t sync_messages_received;
    uint64_t elections_participated;
    uint64_t failovers_initiated;
    uint64_t failovers_completed;
    uint64_t split_brain_events;
    uint64_t quorum_lost_events;
    double avg_sync_latency_ms;
    double avg_election_time_ms;
    double avg_failover_time_ms;
} ha_stats_t;

/**
 * @brief Get HA statistics
 * @param stats Output statistics
 */
void ha_get_stats(ha_stats_t *stats);

/**
 * @brief Reset HA statistics
 */
void ha_reset_stats(void);

/**
 * @brief Print HA status report
 */
void ha_print_status(void);

#endif /* HIGH_AVAILABILITY_H */
