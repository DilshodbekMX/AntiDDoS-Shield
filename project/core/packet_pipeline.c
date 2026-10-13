/**
 * @file packet_pipeline.c
 * @brief Modular Packet Processing Pipeline Implementation
 *
 * Provides a configurable, composable packet processing pipeline.
 * Each stage is isolated and can be enabled/disabled independently.
 */

#include "packet_pipeline.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_malloc.h>
#include <rte_log.h>

#define RTE_LOGTYPE_PIPELINE RTE_LOGTYPE_USER4

/* ==================== Stage Names ==================== */

static const char* stage_names[STAGE_MAX] = {
    [STAGE_PARSE]     = "PARSE",
    [STAGE_VALIDATE]  = "VALIDATE",
    [STAGE_WHITELIST] = "WHITELIST",
    [STAGE_BLACKLIST] = "BLACKLIST",
    [STAGE_GEO]       = "GEO",
    [STAGE_SIGNATURE] = "SIGNATURE",
    [STAGE_POLICY]    = "POLICY",
    [STAGE_REPUTATION]= "REPUTATION",
    [STAGE_PROXY]     = "PROXY",
    [STAGE_CONNLIMIT] = "CONNLIMIT",
    [STAGE_FLOW]      = "FLOW",
    [STAGE_RATELIMIT] = "RATELIMIT",
    [STAGE_FORWARD]   = "FORWARD",
};

static const char* action_names[] = {
    [ACTION_CONTINUE] = "CONTINUE",
    [ACTION_ACCEPT]   = "ACCEPT",
    [ACTION_DROP]     = "DROP",
    [ACTION_REPLY]    = "REPLY",
    [ACTION_REDIRECT] = "REDIRECT",
    [ACTION_MIRROR]   = "MIRROR",
};

static const char* drop_reason_names[] = {
    [DROP_NONE]       = "NONE",
    [DROP_PARSE_ERROR]= "PARSE_ERROR",
    [DROP_VALIDATION] = "VALIDATION",
    [DROP_BLACKLIST]  = "BLACKLIST",
    [DROP_GEO]        = "GEO_BLOCKED",
    [DROP_SIGNATURE]  = "SIGNATURE",
    [DROP_POLICY]     = "POLICY",
    [DROP_REPUTATION] = "REPUTATION",
    [DROP_PROXY]      = "PROXY",
    [DROP_CONNLIMIT]  = "CONN_LIMIT",
    [DROP_FLOW_FULL]  = "FLOW_TABLE_FULL",
    [DROP_RATE_LIMIT] = "RATE_LIMIT",
    [DROP_TTL]        = "TTL_EXPIRED",
};

/* ==================== Utility Functions ==================== */

const char* pipeline_stage_name(pipeline_stage_t id) {
    if (id < STAGE_MAX) {
        return stage_names[id];
    }
    return "UNKNOWN";
}

const char* pipeline_action_name(pipeline_action_t action) {
    if (action <= ACTION_MIRROR) {
        return action_names[action];
    }
    return "UNKNOWN";
}

const char* pipeline_drop_reason_name(pipeline_drop_reason_t reason) {
    if (reason <= DROP_TTL) {
        return drop_reason_names[reason];
    }
    return "UNKNOWN";
}

/* ==================== Context ==================== */

void pipeline_context_init(struct pipeline_context *ctx) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->action = ACTION_CONTINUE;
    ctx->drop_reason = DROP_NONE;
}

/* ==================== Pipeline Lifecycle ==================== */

struct packet_pipeline* pipeline_create(void) {
    struct packet_pipeline *pl = rte_zmalloc("pipeline",
                                             sizeof(struct packet_pipeline),
                                             RTE_CACHE_LINE_SIZE);
    if (!pl) {
        RTE_LOG(ERR, PIPELINE, "Failed to allocate pipeline\n");
        return NULL;
    }

    /* Initialize default stage handlers */
    for (int i = 0; i < STAGE_MAX; i++) {
        pl->stages[i].id = i;
        pl->stages[i].name = stage_names[i];
        pl->stages[i].enabled = false;
    }

    /* Register built-in handlers */
    pl->stages[STAGE_PARSE].handler = stage_parse_handler;
    pl->stages[STAGE_VALIDATE].handler = stage_validate_handler;
    pl->stages[STAGE_WHITELIST].handler = stage_whitelist_handler;
    pl->stages[STAGE_BLACKLIST].handler = stage_blacklist_handler;
    pl->stages[STAGE_GEO].handler = stage_geo_handler;
    pl->stages[STAGE_SIGNATURE].handler = stage_signature_handler;
    pl->stages[STAGE_POLICY].handler = stage_policy_handler;
    pl->stages[STAGE_REPUTATION].handler = stage_reputation_handler;
    pl->stages[STAGE_FLOW].handler = stage_flow_handler;
    pl->stages[STAGE_RATELIMIT].handler = stage_ratelimit_handler;
    pl->stages[STAGE_FORWARD].handler = stage_forward_handler;

    pl->initialized = true;
    RTE_LOG(INFO, PIPELINE, "Pipeline created\n");
    return pl;
}

void pipeline_destroy(struct packet_pipeline *pl) {
    if (pl) {
        pl->initialized = false;
        rte_free(pl);
        RTE_LOG(INFO, PIPELINE, "Pipeline destroyed\n");
    }
}

/* ==================== Stage Management ==================== */

int pipeline_register_stage(struct packet_pipeline *pl,
                            pipeline_stage_t id,
                            stage_handler_fn handler,
                            void *config,
                            const char *name) {
    if (!pl || id >= STAGE_MAX || !handler) {
        return -1;
    }

    pl->stages[id].handler = handler;
    pl->stages[id].config = config;
    if (name) {
        pl->stages[id].name = name;
    }

    RTE_LOG(DEBUG, PIPELINE, "Registered stage %s (id=%d)\n", name ? name : stage_names[id], id);
    return 0;
}

int pipeline_enable_stage(struct packet_pipeline *pl, pipeline_stage_t id) {
    if (!pl || id >= STAGE_MAX) {
        return -1;
    }

    if (!pl->stages[id].enabled) {
        pl->stages[id].enabled = true;
        pl->enabled_count++;
        RTE_LOG(DEBUG, PIPELINE, "Enabled stage %s\n", pl->stages[id].name);
    }
    return 0;
}

int pipeline_disable_stage(struct packet_pipeline *pl, pipeline_stage_t id) {
    if (!pl || id >= STAGE_MAX) {
        return -1;
    }

    if (pl->stages[id].enabled) {
        pl->stages[id].enabled = false;
        pl->enabled_count--;
        RTE_LOG(DEBUG, PIPELINE, "Disabled stage %s\n", pl->stages[id].name);
    }
    return 0;
}

bool pipeline_stage_enabled(struct packet_pipeline *pl, pipeline_stage_t id) {
    if (!pl || id >= STAGE_MAX) {
        return false;
    }
    return pl->stages[id].enabled;
}

void pipeline_set_inbound_only(struct packet_pipeline *pl, pipeline_stage_t id) {
    if (pl && id < STAGE_MAX) {
        pl->stages[id].inbound_only = true;
        pl->stages[id].outbound_only = false;
    }
}

void pipeline_set_outbound_only(struct packet_pipeline *pl, pipeline_stage_t id) {
    if (pl && id < STAGE_MAX) {
        pl->stages[id].outbound_only = true;
        pl->stages[id].inbound_only = false;
    }
}

void pipeline_set_mempool(struct packet_pipeline *pl, struct rte_mempool *pool) {
    if (pl) {
        pl->mempool = pool;
    }
}

/* ==================== Pipeline Processing ==================== */

int pipeline_process(struct packet_pipeline *pl,
                     struct rte_mbuf *mbuf,
                     uint16_t port_id,
                     uint16_t queue_id,
                     struct pipeline_context *ctx) {
    if (!pl || !pl->initialized || !mbuf || !ctx) {
        return -1;
    }

    /* Initialize context */
    pipeline_context_init(ctx);
    ctx->mbuf = mbuf;
    ctx->port_id = port_id;
    ctx->queue_id = queue_id;
    ctx->packet_size = mbuf->pkt_len;
    ctx->start_cycles = rte_rdtsc();

    /* Determine direction based on port (simple heuristic) */
    ctx->direction = (port_id == 0) ? 0 : 1;  /* 0=inbound, 1=outbound */

    /* Process through enabled stages */
    pipeline_action_t action = ACTION_CONTINUE;

    for (int i = 0; i < STAGE_MAX && action == ACTION_CONTINUE; i++) {
        struct pipeline_stage *stage = &pl->stages[i];

        if (!stage->enabled || !stage->handler) {
            continue;
        }

        /* Check direction constraints */
        if (stage->inbound_only && ctx->direction != 0) {
            continue;
        }
        if (stage->outbound_only && ctx->direction != 1) {
            continue;
        }

        /* Execute stage */
        uint64_t stage_start = rte_rdtsc();

        action = stage->handler(ctx, stage->config);

        uint64_t stage_cycles = rte_rdtsc() - stage_start;
        ctx->stage_cycles[i] = stage_cycles;
        ctx->stage_mask |= (1ULL << i);
        ctx->last_stage = i;

        /* Update stage stats -- multiple lcores call this concurrently */
        __atomic_fetch_add(&stage->packets_processed, 1, __ATOMIC_RELAXED);
        __atomic_fetch_add(&stage->total_cycles, stage_cycles, __ATOMIC_RELAXED);

        if (action == ACTION_DROP) {
            __atomic_fetch_add(&stage->packets_dropped, 1, __ATOMIC_RELAXED);
        }
    }

    /* Store final action */
    ctx->action = action;

    /* Update pipeline stats -- multiple lcores call this concurrently */
    __atomic_fetch_add(&pl->total_packets, 1, __ATOMIC_RELAXED);
    __atomic_fetch_add(&pl->total_cycles, (rte_rdtsc() - ctx->start_cycles), __ATOMIC_RELAXED);

    if (action == ACTION_DROP) {
        __atomic_fetch_add(&pl->total_dropped, 1, __ATOMIC_RELAXED);
    } else if (action == ACTION_ACCEPT || action == ACTION_CONTINUE) {
        __atomic_fetch_add(&pl->total_accepted, 1, __ATOMIC_RELAXED);
        ctx->action = ACTION_ACCEPT;  /* CONTINUE at end means ACCEPT */
    }

    return 0;
}

/* ==================== Statistics ==================== */

void pipeline_get_stats(struct packet_pipeline *pl, struct pipeline_stats *stats) {
    if (!pl || !stats) {
        return;
    }

    memset(stats, 0, sizeof(*stats));
    stats->total_packets = pl->total_packets;
    stats->total_accepted = pl->total_accepted;
    stats->total_dropped = pl->total_dropped;

    if (pl->total_packets > 0) {
        stats->avg_cycles = pl->total_cycles / pl->total_packets;
    }

    for (int i = 0; i < STAGE_MAX; i++) {
        stats->stage_packets[i] = pl->stages[i].packets_processed;
        stats->stage_drops[i] = pl->stages[i].packets_dropped;
        if (pl->stages[i].packets_processed > 0) {
            stats->stage_cycles[i] = pl->stages[i].total_cycles /
                                     pl->stages[i].packets_processed;
        }
    }
}

void pipeline_reset_stats(struct packet_pipeline *pl) {
    if (!pl) {
        return;
    }

    pl->total_packets = 0;
    pl->total_accepted = 0;
    pl->total_dropped = 0;
    pl->total_cycles = 0;

    for (int i = 0; i < STAGE_MAX; i++) {
        pl->stages[i].packets_processed = 0;
        pl->stages[i].packets_dropped = 0;
        pl->stages[i].total_cycles = 0;
    }
}

void pipeline_print_stats(struct packet_pipeline *pl) {
    if (!pl) {
        return;
    }

    struct pipeline_stats stats;
    pipeline_get_stats(pl, &stats);

    printf("\n=== Pipeline Statistics ===\n");
    printf("Total packets:   %lu\n", stats.total_packets);
    printf("Accepted:        %lu (%.2f%%)\n", stats.total_accepted,
           stats.total_packets ? 100.0 * stats.total_accepted / stats.total_packets : 0);
    printf("Dropped:         %lu (%.2f%%)\n", stats.total_dropped,
           stats.total_packets ? 100.0 * stats.total_dropped / stats.total_packets : 0);
    printf("Avg cycles/pkt:  %lu\n", stats.avg_cycles);
    printf("\n--- Stage Statistics ---\n");
    printf("%-12s %12s %12s %12s %8s\n", "Stage", "Packets", "Drops", "Cycles/pkt", "Enabled");
    printf("%-12s %12s %12s %12s %8s\n", "-----", "-------", "-----", "----------", "-------");

    for (int i = 0; i < STAGE_MAX; i++) {
        if (pl->stages[i].packets_processed > 0 || pl->stages[i].enabled) {
            printf("%-12s %12lu %12lu %12lu %8s\n",
                   pl->stages[i].name,
                   stats.stage_packets[i],
                   stats.stage_drops[i],
                   stats.stage_cycles[i],
                   pl->stages[i].enabled ? "yes" : "no");
        }
    }
    printf("============================\n\n");
}

/* ==================== Built-in Stage Handlers ==================== */

/*
 * Note: These are stub implementations. In a real deployment,
 * they would call into the actual layer1 modules.
 */

pipeline_action_t stage_parse_handler(struct pipeline_context *ctx, void *config) {
    (void)config;

    if (!ctx || !ctx->mbuf) {
        return ACTION_DROP;
    }

    /* Basic Ethernet + IP parsing */
    if (ctx->mbuf->pkt_len < 14) {
        ctx->drop_reason = DROP_PARSE_ERROR;
        return ACTION_DROP;
    }

    uint8_t *data = rte_pktmbuf_mtod(ctx->mbuf, uint8_t *);
    uint16_t ethertype = (data[12] << 8) | data[13];

    if (ethertype == 0x0800) {  /* IPv4 */
        if (ctx->mbuf->pkt_len < 34) {
            ctx->drop_reason = DROP_PARSE_ERROR;
            return ACTION_DROP;
        }
        ctx->ip_version = 4;
        ctx->src_ip = *(uint32_t *)(data + 26);
        ctx->dst_ip = *(uint32_t *)(data + 30);
        ctx->protocol = data[23];
        ctx->ttl = data[22];
    } else if (ethertype == 0x86DD) {  /* IPv6 */
        if (ctx->mbuf->pkt_len < 54) {
            ctx->drop_reason = DROP_PARSE_ERROR;
            return ACTION_DROP;
        }
        ctx->ip_version = 6;
        ctx->protocol = data[20];
        ctx->ttl = data[21];
    } else {
        /* Non-IP packet - pass through */
        return ACTION_ACCEPT;
    }

    /* Parse TCP/UDP ports */
    if (ctx->ip_version == 4) {
        size_t ip_hdr_len = (data[14] & 0x0F) * 4;
        size_t l4_offset = 14 + ip_hdr_len;

        if (ctx->protocol == 6 || ctx->protocol == 17) {  /* TCP or UDP */
            if (ctx->mbuf->pkt_len >= l4_offset + 4) {
                ctx->src_port = (data[l4_offset] << 8) | data[l4_offset + 1];
                ctx->dst_port = (data[l4_offset + 2] << 8) | data[l4_offset + 3];
            }
            if (ctx->protocol == 6 && ctx->mbuf->pkt_len >= l4_offset + 14) {
                ctx->tcp_flags = data[l4_offset + 13];
            }
        }
    }

    return ACTION_CONTINUE;
}

pipeline_action_t stage_validate_handler(struct pipeline_context *ctx, void *config) {
    (void)config;

    if (!ctx) {
        return ACTION_DROP;
    }

    /* TTL check */
    if (ctx->ttl == 0) {
        ctx->drop_reason = DROP_TTL;
        return ACTION_DROP;
    }

    /* Basic validation passed */
    return ACTION_CONTINUE;
}

pipeline_action_t stage_whitelist_handler(struct pipeline_context *ctx, void *config) {
    (void)config;
    (void)ctx;
    /* In real implementation, check ip_whitelist_lookup(ctx->src_ip) */
    return ACTION_CONTINUE;
}

pipeline_action_t stage_blacklist_handler(struct pipeline_context *ctx, void *config) {
    (void)config;
    (void)ctx;
    /* In real implementation, check ip_blacklist_lookup(ctx->src_ip) */
    return ACTION_CONTINUE;
}

pipeline_action_t stage_geo_handler(struct pipeline_context *ctx, void *config) {
    (void)config;
    (void)ctx;
    /* In real implementation, check geo_should_block(ctx->src_ip) */
    return ACTION_CONTINUE;
}

pipeline_action_t stage_signature_handler(struct pipeline_context *ctx, void *config) {
    (void)config;
    (void)ctx;
    /* In real implementation, check signatures_check(...) */
    return ACTION_CONTINUE;
}

pipeline_action_t stage_policy_handler(struct pipeline_context *ctx, void *config) {
    (void)config;
    (void)ctx;
    /* In real implementation, check policy_lookup(...) */
    return ACTION_CONTINUE;
}

pipeline_action_t stage_reputation_handler(struct pipeline_context *ctx, void *config) {
    (void)config;
    (void)ctx;
    /* In real implementation, check reputation_lookup(...) */
    return ACTION_CONTINUE;
}

pipeline_action_t stage_flow_handler(struct pipeline_context *ctx, void *config) {
    (void)config;
    (void)ctx;
    /* In real implementation, call flow_table_lookup_or_create(...) */
    return ACTION_CONTINUE;
}

pipeline_action_t stage_ratelimit_handler(struct pipeline_context *ctx, void *config) {
    (void)config;
    (void)ctx;
    /* In real implementation, call flow_table_check_rate_limit(...) */
    return ACTION_CONTINUE;
}

pipeline_action_t stage_forward_handler(struct pipeline_context *ctx, void *config) {
    (void)config;
    (void)ctx;
    /* Final forwarding decision */
    return ACTION_ACCEPT;
}
