/**
 * @file packet_pipeline.h
 * @brief Modular Packet Processing Pipeline Abstraction
 *
 * Provides a configurable packet processing pipeline with composable stages.
 * Each stage can inspect, modify, or drop packets, enabling flexible
 * protection strategies.
 *
 * Pipeline Stages:
 *   1. PARSE     - Parse packet headers, extract features
 *   2. VALIDATE  - Validate headers, checksums, protocol sanity
 *   3. WHITELIST - Fast-path accept for trusted IPs
 *   4. BLACKLIST - Fast-path reject for blocked IPs
 *   5. GEO       - Geographic blocking
 *   6. SIGNATURE - Attack signature detection
 *   7. POLICY    - Policy-based filtering
 *   8. REPUTATION- IP reputation scoring
 *   9. PROXY     - SYN proxy (TCP only)
 *   10. CONNLIMIT- Connection limiting
 *   11. FLOW     - Flow tracking and rate limiting
 *   12. FORWARD  - Final forwarding decision
 *
 * Usage:
 *   struct packet_pipeline *pl = pipeline_create();
 *   pipeline_enable_stage(pl, STAGE_PARSE);
 *   pipeline_enable_stage(pl, STAGE_VALIDATE);
 *   pipeline_enable_stage(pl, STAGE_BLACKLIST);
 *   // ... enable other stages ...
 *
 *   // In packet processing loop:
 *   struct pipeline_result result;
 *   pipeline_process(pl, mbuf, port_id, &result);
 */

#ifndef CORE_PACKET_PIPELINE_H
#define CORE_PACKET_PIPELINE_H

#include <stdint.h>
#include <stdbool.h>
#include <rte_mbuf.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ==================== Pipeline Stage IDs ==================== */

typedef enum {
    STAGE_PARSE         = 0,   /* Parse headers */
    STAGE_VALIDATE      = 1,   /* Validate packet */
    STAGE_WHITELIST     = 2,   /* Whitelist check */
    STAGE_BLACKLIST     = 3,   /* Blacklist check */
    STAGE_GEO           = 4,   /* Geographic blocking */
    STAGE_SIGNATURE     = 5,   /* Attack signatures */
    STAGE_POLICY        = 6,   /* Policy enforcement */
    STAGE_REPUTATION    = 7,   /* Reputation check */
    STAGE_PROXY         = 8,   /* SYN proxy */
    STAGE_CONNLIMIT     = 9,   /* Connection limits */
    STAGE_FLOW          = 10,  /* Flow tracking */
    STAGE_RATELIMIT     = 11,  /* Rate limiting */
    STAGE_FORWARD       = 12,  /* Forwarding */
    STAGE_MAX           = 13
} pipeline_stage_t;

/* ==================== Pipeline Actions ==================== */

typedef enum {
    ACTION_CONTINUE     = 0,   /* Continue to next stage */
    ACTION_ACCEPT       = 1,   /* Accept packet, skip remaining stages */
    ACTION_DROP         = 2,   /* Drop packet */
    ACTION_REPLY        = 3,   /* Send reply packet */
    ACTION_REDIRECT     = 4,   /* Redirect to different port */
    ACTION_MIRROR       = 5,   /* Mirror packet */
} pipeline_action_t;

/* ==================== Drop Reasons ==================== */

typedef enum {
    DROP_NONE           = 0,
    DROP_PARSE_ERROR    = 1,
    DROP_VALIDATION     = 2,
    DROP_BLACKLIST      = 3,
    DROP_GEO            = 4,
    DROP_SIGNATURE      = 5,
    DROP_POLICY         = 6,
    DROP_REPUTATION     = 7,
    DROP_PROXY          = 8,
    DROP_CONNLIMIT      = 9,
    DROP_FLOW_FULL      = 10,
    DROP_RATE_LIMIT     = 11,
    DROP_TTL            = 12,
} pipeline_drop_reason_t;

/* ==================== Pipeline Context ==================== */

/**
 * Per-packet context passed through pipeline stages
 */
struct pipeline_context {
    /* Input */
    struct rte_mbuf *mbuf;          /* Packet mbuf */
    uint16_t port_id;               /* Input port */
    uint16_t queue_id;              /* Input queue */
    uint8_t  direction;             /* Inbound/Outbound */

    /* Parsed features (filled by STAGE_PARSE) */
    uint32_t src_ip;                /* Source IP (network order) */
    uint32_t dst_ip;                /* Destination IP (network order) */
    uint16_t src_port;              /* Source port (host order) */
    uint16_t dst_port;              /* Destination port (host order) */
    uint8_t  protocol;              /* IP protocol */
    uint8_t  tcp_flags;             /* TCP flags */
    uint8_t  ip_version;            /* 4 or 6 */
    uint8_t  ttl;                   /* TTL/hop limit */
    uint16_t packet_size;           /* Packet length */
    uint32_t flow_hash;             /* Flow hash */

    /* Stage results */
    uint64_t stage_mask;            /* Bitmask of stages executed */
    pipeline_stage_t last_stage;    /* Last stage executed */
    pipeline_action_t action;       /* Final action */
    pipeline_drop_reason_t drop_reason;

    /* Output packets */
    struct rte_mbuf *reply_pkt;     /* Reply packet (if any) */
    uint16_t reply_port;
    uint16_t reply_queue;

    /* Flow state */
    void *flow;                     /* Flow entry pointer */
    bool  new_flow;                 /* True if flow was just created */

    /* Metrics */
    uint64_t start_cycles;          /* TSC at pipeline start */
    uint64_t stage_cycles[STAGE_MAX]; /* Cycles per stage */

    /* User data */
    void *user_data;
};

/* ==================== Stage Handler ==================== */

/**
 * Stage handler function type
 *
 * @param ctx    Pipeline context (packet features, state)
 * @param config Stage-specific configuration
 * @return Action to take (CONTINUE, ACCEPT, DROP, etc.)
 */
typedef pipeline_action_t (*stage_handler_fn)(struct pipeline_context *ctx,
                                              void *config);

/**
 * Stage definition
 */
struct pipeline_stage {
    const char         *name;       /* Stage name (for logging) */
    pipeline_stage_t    id;         /* Stage ID */
    stage_handler_fn    handler;    /* Handler function */
    void               *config;     /* Stage configuration */
    bool                enabled;    /* Is stage active? */
    bool                inbound_only;   /* Only for inbound traffic */
    bool                outbound_only;  /* Only for outbound traffic */
    uint64_t            packets_processed;
    uint64_t            packets_dropped;
    uint64_t            total_cycles;
};

/* ==================== Pipeline Structure ==================== */

struct packet_pipeline {
    struct pipeline_stage stages[STAGE_MAX];
    uint32_t enabled_count;         /* Number of enabled stages */
    uint64_t total_packets;
    uint64_t total_accepted;
    uint64_t total_dropped;
    uint64_t total_cycles;
    bool     initialized;
    struct rte_mempool *mempool;    /* Packet pool for replies */
};

/* ==================== Pipeline API ==================== */

/**
 * Create a new packet pipeline
 *
 * @return Pipeline instance or NULL on error
 */
struct packet_pipeline* pipeline_create(void);

/**
 * Destroy a pipeline
 */
void pipeline_destroy(struct packet_pipeline *pl);

/**
 * Register a custom stage handler
 *
 * @param pl      Pipeline
 * @param id      Stage ID
 * @param handler Handler function
 * @param config  Stage configuration
 * @param name    Stage name (for logging)
 * @return 0 on success, -1 on error
 */
int pipeline_register_stage(struct packet_pipeline *pl,
                            pipeline_stage_t id,
                            stage_handler_fn handler,
                            void *config,
                            const char *name);

/**
 * Enable a pipeline stage
 */
int pipeline_enable_stage(struct packet_pipeline *pl, pipeline_stage_t id);

/**
 * Disable a pipeline stage
 */
int pipeline_disable_stage(struct packet_pipeline *pl, pipeline_stage_t id);

/**
 * Check if a stage is enabled
 */
bool pipeline_stage_enabled(struct packet_pipeline *pl, pipeline_stage_t id);

/**
 * Set stage for inbound-only processing
 */
void pipeline_set_inbound_only(struct packet_pipeline *pl, pipeline_stage_t id);

/**
 * Set stage for outbound-only processing
 */
void pipeline_set_outbound_only(struct packet_pipeline *pl, pipeline_stage_t id);

/**
 * Set the mempool for reply packet allocation
 */
void pipeline_set_mempool(struct packet_pipeline *pl, struct rte_mempool *pool);

/* ==================== Packet Processing ==================== */

/**
 * Process a packet through the pipeline
 *
 * @param pl        Pipeline
 * @param mbuf      Packet mbuf
 * @param port_id   Input port
 * @param queue_id  Input queue
 * @param ctx       Output context with results
 * @return 0 on success, -1 on error
 */
int pipeline_process(struct packet_pipeline *pl,
                     struct rte_mbuf *mbuf,
                     uint16_t port_id,
                     uint16_t queue_id,
                     struct pipeline_context *ctx);

/**
 * Initialize pipeline context
 */
void pipeline_context_init(struct pipeline_context *ctx);

/* ==================== Statistics ==================== */

/**
 * Pipeline statistics
 */
struct pipeline_stats {
    uint64_t total_packets;
    uint64_t total_accepted;
    uint64_t total_dropped;
    uint64_t avg_cycles;
    uint64_t stage_packets[STAGE_MAX];
    uint64_t stage_drops[STAGE_MAX];
    uint64_t stage_cycles[STAGE_MAX];
};

/**
 * Get pipeline statistics
 */
void pipeline_get_stats(struct packet_pipeline *pl, struct pipeline_stats *stats);

/**
 * Reset pipeline statistics
 */
void pipeline_reset_stats(struct packet_pipeline *pl);

/**
 * Print pipeline statistics
 */
void pipeline_print_stats(struct packet_pipeline *pl);

/* ==================== Built-in Stage Handlers ==================== */

/* Parse stage - extract packet features */
pipeline_action_t stage_parse_handler(struct pipeline_context *ctx, void *config);

/* Validate stage - validate headers and checksums */
pipeline_action_t stage_validate_handler(struct pipeline_context *ctx, void *config);

/* Whitelist stage - check source IP whitelist */
pipeline_action_t stage_whitelist_handler(struct pipeline_context *ctx, void *config);

/* Blacklist stage - check source IP blacklist */
pipeline_action_t stage_blacklist_handler(struct pipeline_context *ctx, void *config);

/* Geo stage - geographic blocking */
pipeline_action_t stage_geo_handler(struct pipeline_context *ctx, void *config);

/* Signature stage - attack signature detection */
pipeline_action_t stage_signature_handler(struct pipeline_context *ctx, void *config);

/* Policy stage - policy enforcement */
pipeline_action_t stage_policy_handler(struct pipeline_context *ctx, void *config);

/* Reputation stage - IP reputation check */
pipeline_action_t stage_reputation_handler(struct pipeline_context *ctx, void *config);

/* Flow stage - flow tracking */
pipeline_action_t stage_flow_handler(struct pipeline_context *ctx, void *config);

/* Rate limit stage - per-flow rate limiting */
pipeline_action_t stage_ratelimit_handler(struct pipeline_context *ctx, void *config);

/* Forward stage - final forwarding decision */
pipeline_action_t stage_forward_handler(struct pipeline_context *ctx, void *config);

/* ==================== Utilities ==================== */

/**
 * Get stage name string
 */
const char* pipeline_stage_name(pipeline_stage_t id);

/**
 * Get action name string
 */
const char* pipeline_action_name(pipeline_action_t action);

/**
 * Get drop reason string
 */
const char* pipeline_drop_reason_name(pipeline_drop_reason_t reason);

#ifdef __cplusplus
}
#endif

#endif /* CORE_PACKET_PIPELINE_H */
