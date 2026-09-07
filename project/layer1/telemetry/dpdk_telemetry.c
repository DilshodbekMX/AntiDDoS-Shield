#include "dpdk_telemetry.h"
#include "../layer1.h"
#include "../tables/flow_table.h"
#include "../tables/syn_proxy.h"
#include "../tables/ip_lists.h"
#include "../tables/udp_gatekeeper.h"
#include "../telemetry/hyperloglog.h"
#include "../../core/dpdk_core.h"

#include <rte_telemetry.h>
#include <rte_lcore.h>
#include <rte_version.h>

#define RTE_LOGTYPE_L1TEL RTE_LOGTYPE_USER5

// ==================== /antiddos/info ====================

static int
handle_info(const char *cmd __rte_unused,
            const char *params __rte_unused,
            struct rte_tel_data *d)
{
    rte_tel_data_start_dict(d);
    rte_tel_data_add_dict_string(d, "component", "Layer 1 Anti-DDoS");
    rte_tel_data_add_dict_string(d, "version", "1.0.0");
    rte_tel_data_add_dict_string(d, "dpdk_version", rte_version());
    rte_tel_data_add_dict_int(d, "initialized", layer1_is_initialized() ? 1 : 0);
    rte_tel_data_add_dict_int(d, "syn_proxy_enabled", syn_proxy_is_enabled() ? 1 : 0);
    rte_tel_data_add_dict_int(d, "num_lcores", rte_lcore_count());
    return 0;
}

// ==================== /antiddos/stats ====================

static int
handle_stats(const char *cmd __rte_unused,
             const char *params __rte_unused,
             struct rte_tel_data *d)
{
    struct layer1_stats stats;
    layer1_get_stats(&stats);

    rte_tel_data_start_dict(d);

    // Packet counts
    rte_tel_data_add_dict_uint(d, "total_packets", stats.total_packets);
    rte_tel_data_add_dict_uint(d, "total_bytes", stats.total_bytes);
    rte_tel_data_add_dict_uint(d, "packets_accepted", stats.packets_accepted);
    rte_tel_data_add_dict_uint(d, "packets_dropped", stats.packets_dropped);

    // Direction breakdown
    rte_tel_data_add_dict_uint(d, "inbound_packets", stats.inbound_packets);
    rte_tel_data_add_dict_uint(d, "inbound_bytes", stats.inbound_bytes);
    rte_tel_data_add_dict_uint(d, "outbound_packets", stats.outbound_packets);
    rte_tel_data_add_dict_uint(d, "outbound_bytes", stats.outbound_bytes);

    // Flow stats
    rte_tel_data_add_dict_uint(d, "active_flows", stats.active_flows);
    rte_tel_data_add_dict_uint(d, "total_flows_created", stats.total_flows_created);

    // SYN proxy
    rte_tel_data_add_dict_uint(d, "syn_proxy_challenges", stats.syn_proxy_challenges);
    rte_tel_data_add_dict_uint(d, "syn_proxy_established", stats.syn_proxy_established);
    rte_tel_data_add_dict_uint(d, "syn_proxy_active", stats.syn_proxy_active);

    // Whitelist
    rte_tel_data_add_dict_uint(d, "whitelist_hits", stats.whitelist_hits);

    return 0;
}

// ==================== /antiddos/drop_reasons ====================

static int
handle_drop_reasons(const char *cmd __rte_unused,
                    const char *params __rte_unused,
                    struct rte_tel_data *d)
{
    struct layer1_stats stats;
    layer1_get_stats(&stats);

    rte_tel_data_start_dict(d);
    rte_tel_data_add_dict_uint(d, "validation", stats.drop_validation);
    rte_tel_data_add_dict_uint(d, "blacklist", stats.drop_blacklist);
    rte_tel_data_add_dict_uint(d, "rate_limit", stats.drop_rate_limit);
    rte_tel_data_add_dict_uint(d, "syn_flood", stats.drop_syn_flood);
    rte_tel_data_add_dict_uint(d, "reputation", stats.drop_reputation);
    rte_tel_data_add_dict_uint(d, "policy", stats.drop_policy);
    rte_tel_data_add_dict_uint(d, "proxy_error", stats.drop_proxy_error);

    return 0;
}

// ==================== /antiddos/flow_table ====================

static int
handle_flow_table(const char *cmd __rte_unused,
                  const char *params __rte_unused,
                  struct rte_tel_data *d)
{
    struct flow_table_stats fstats;
    uint32_t active_flows, total_flows, aged_flows;

    flow_table_get_stats(&active_flows, &total_flows, &aged_flows);
    flow_table_get_detailed_stats(&fstats);

    rte_tel_data_start_dict(d);
    rte_tel_data_add_dict_uint(d, "active_flows", active_flows);
    rte_tel_data_add_dict_uint(d, "total_created", total_flows);
    rte_tel_data_add_dict_uint(d, "aged_flows", aged_flows);
    rte_tel_data_add_dict_uint(d, "lookups", fstats.lookups);
    rte_tel_data_add_dict_uint(d, "lookup_hits", fstats.lookup_hits);
    rte_tel_data_add_dict_uint(d, "creates", fstats.creates);
    rte_tel_data_add_dict_uint(d, "create_failures", fstats.create_failures);
    rte_tel_data_add_dict_uint(d, "updates", fstats.updates);
    rte_tel_data_add_dict_uint(d, "rate_limit_drops", fstats.rate_limit_drops);

    // Calculate hit rate
    if (fstats.lookups > 0) {
        double hit_rate = (double)fstats.lookup_hits / fstats.lookups * 100.0;
        rte_tel_data_add_dict_int(d, "hit_rate_pct", (int)hit_rate);
    } else {
        rte_tel_data_add_dict_int(d, "hit_rate_pct", 0);
    }

    return 0;
}

// ==================== /antiddos/syn_proxy ====================

static int
handle_syn_proxy(const char *cmd __rte_unused,
                 const char *params __rte_unused,
                 struct rte_tel_data *d)
{
    struct syn_proxy_stats pstats;
    syn_proxy_get_stats(&pstats);

    rte_tel_data_start_dict(d);
    rte_tel_data_add_dict_int(d, "enabled", syn_proxy_is_enabled() ? 1 : 0);
    rte_tel_data_add_dict_uint(d, "connections_active", pstats.connections_active);
    rte_tel_data_add_dict_uint(d, "connections_established", pstats.connections_established);
    rte_tel_data_add_dict_uint(d, "cookies_sent", pstats.cookies_sent);
    rte_tel_data_add_dict_uint(d, "cookies_valid", pstats.cookies_valid);
    rte_tel_data_add_dict_uint(d, "cookies_invalid", pstats.cookies_invalid);
    rte_tel_data_add_dict_uint(d, "cookies_expired", pstats.cookies_expired);
    rte_tel_data_add_dict_uint(d, "packets_bypassed", pstats.packets_bypassed);

    // Calculate validation rate
    uint64_t total_cookies = pstats.cookies_valid + pstats.cookies_invalid + pstats.cookies_expired;
    if (total_cookies > 0) {
        double valid_rate = (double)pstats.cookies_valid / total_cookies * 100.0;
        rte_tel_data_add_dict_int(d, "cookie_valid_rate_pct", (int)valid_rate);
    } else {
        rte_tel_data_add_dict_int(d, "cookie_valid_rate_pct", 100);
    }

    return 0;
}

// ==================== /antiddos/ip_lists ====================

static int
handle_ip_lists(const char *cmd __rte_unused,
                const char *params __rte_unused,
                struct rte_tel_data *d)
{
    rte_tel_data_start_dict(d);
    rte_tel_data_add_dict_uint(d, "whitelist_count", ip_whitelist_count());
    rte_tel_data_add_dict_uint(d, "blacklist_count", ip_blacklist_count());
    rte_tel_data_add_dict_uint(d, "protected_count", ip_protected_count());
    rte_tel_data_add_dict_int(d, "protected_enforcement",
                               ip_protected_enforcement_enabled() ? 1 : 0);

    return 0;
}

// ==================== /antiddos/udp_gatekeeper ====================

static int
handle_udp_gatekeeper(const char *cmd __rte_unused,
                      const char *params __rte_unused,
                      struct rte_tel_data *d)
{
    struct udp_gatekeeper_stats gkstats;
    udp_gatekeeper_get_stats(&gkstats);

    rte_tel_data_start_dict(d);
    rte_tel_data_add_dict_uint(d, "packets_checked", gkstats.packets_checked);
    rte_tel_data_add_dict_uint(d, "packets_accepted", gkstats.packets_accepted);
    rte_tel_data_add_dict_uint(d, "drops_pps", gkstats.drops_pps);
    rte_tel_data_add_dict_uint(d, "drops_bps", gkstats.drops_bps);
    rte_tel_data_add_dict_uint(d, "drops_reputation", gkstats.drops_reputation);
    rte_tel_data_add_dict_uint(d, "drops_blacklist", gkstats.drops_blacklist);
    rte_tel_data_add_dict_uint(d, "unique_ips_approx", gkstats.unique_ips_approx);
    rte_tel_data_add_dict_uint(d, "cms_rotations", gkstats.cms_rotations);

    return 0;
}

// ==================== /antiddos/cardinality ====================

static int
handle_cardinality(const char *cmd __rte_unused,
                   const char *params __rte_unused,
                   struct rte_tel_data *d)
{
    rte_tel_data_start_dict(d);

    // Get HLL estimates for unique source IPs
    uint64_t unique_src_ips = hll_global_src_ip_count();
    rte_tel_data_add_dict_uint(d, "unique_src_ips", unique_src_ips);

    return 0;
}

// ==================== /antiddos/per_lcore ====================

static int
handle_per_lcore(const char *cmd __rte_unused,
                 const char *params __rte_unused,
                 struct rte_tel_data *d)
{
    rte_tel_data_start_dict(d);

    unsigned int lcore_id;
    char key[32];

    RTE_LCORE_FOREACH(lcore_id) {
        struct lcore_stats *lstats = &lcore_statistics[lcore_id];

        // Create a nested dict for each lcore with key stats
        struct rte_tel_data *lcore_data = rte_tel_data_alloc();
        if (!lcore_data) continue;

        rte_tel_data_start_dict(lcore_data);
        rte_tel_data_add_dict_uint(lcore_data, "rx_packets", lstats->rx_packets);
        rte_tel_data_add_dict_uint(lcore_data, "tx_packets", lstats->tx_packets);
        rte_tel_data_add_dict_uint(lcore_data, "dropped", lstats->dropped);
        rte_tel_data_add_dict_uint(lcore_data, "l1_total", lstats->l1_total_packets);
        rte_tel_data_add_dict_uint(lcore_data, "l1_accepted", lstats->l1_packets_accepted);
        rte_tel_data_add_dict_uint(lcore_data, "l1_dropped", lstats->l1_packets_dropped);

        snprintf(key, sizeof(key), "lcore_%u", lcore_id);
        rte_tel_data_add_dict_container(d, key, lcore_data, 0);
    }

    return 0;
}

// ==================== Initialization ====================

int dpdk_telemetry_init(void)
{
    int ret;

    RTE_LOG(INFO, L1TEL, "Registering DPDK telemetry endpoints\n");

    // Register all endpoints
    ret = rte_telemetry_register_cmd("/antiddos/info", handle_info,
            "Returns Layer 1 system information");
    if (ret < 0) {
        RTE_LOG(WARNING, L1TEL, "Failed to register /antiddos/info\n");
    }

    ret = rte_telemetry_register_cmd("/antiddos/stats", handle_stats,
            "Returns aggregated packet statistics");
    if (ret < 0) {
        RTE_LOG(WARNING, L1TEL, "Failed to register /antiddos/stats\n");
    }

    ret = rte_telemetry_register_cmd("/antiddos/drop_reasons", handle_drop_reasons,
            "Returns drop reason breakdown");
    if (ret < 0) {
        RTE_LOG(WARNING, L1TEL, "Failed to register /antiddos/drop_reasons\n");
    }

    ret = rte_telemetry_register_cmd("/antiddos/flow_table", handle_flow_table,
            "Returns flow table statistics");
    if (ret < 0) {
        RTE_LOG(WARNING, L1TEL, "Failed to register /antiddos/flow_table\n");
    }

    ret = rte_telemetry_register_cmd("/antiddos/syn_proxy", handle_syn_proxy,
            "Returns SYN proxy statistics");
    if (ret < 0) {
        RTE_LOG(WARNING, L1TEL, "Failed to register /antiddos/syn_proxy\n");
    }

    ret = rte_telemetry_register_cmd("/antiddos/ip_lists", handle_ip_lists,
            "Returns IP list statistics");
    if (ret < 0) {
        RTE_LOG(WARNING, L1TEL, "Failed to register /antiddos/ip_lists\n");
    }

    ret = rte_telemetry_register_cmd("/antiddos/udp_gatekeeper", handle_udp_gatekeeper,
            "Returns UDP gatekeeper statistics");
    if (ret < 0) {
        RTE_LOG(WARNING, L1TEL, "Failed to register /antiddos/udp_gatekeeper\n");
    }

    ret = rte_telemetry_register_cmd("/antiddos/cardinality", handle_cardinality,
            "Returns cardinality estimates (unique IPs)");
    if (ret < 0) {
        RTE_LOG(WARNING, L1TEL, "Failed to register /antiddos/cardinality\n");
    }

    ret = rte_telemetry_register_cmd("/antiddos/per_lcore", handle_per_lcore,
            "Returns per-lcore statistics");
    if (ret < 0) {
        RTE_LOG(WARNING, L1TEL, "Failed to register /antiddos/per_lcore\n");
    }

    RTE_LOG(INFO, L1TEL, "DPDK telemetry endpoints registered:\n");
    RTE_LOG(INFO, L1TEL, "  /antiddos/info\n");
    RTE_LOG(INFO, L1TEL, "  /antiddos/stats\n");
    RTE_LOG(INFO, L1TEL, "  /antiddos/drop_reasons\n");
    RTE_LOG(INFO, L1TEL, "  /antiddos/flow_table\n");
    RTE_LOG(INFO, L1TEL, "  /antiddos/syn_proxy\n");
    RTE_LOG(INFO, L1TEL, "  /antiddos/ip_lists\n");
    RTE_LOG(INFO, L1TEL, "  /antiddos/udp_gatekeeper\n");
    RTE_LOG(INFO, L1TEL, "  /antiddos/cardinality\n");
    RTE_LOG(INFO, L1TEL, "  /antiddos/per_lcore\n");
    RTE_LOG(INFO, L1TEL, "Access via: dpdk-telemetry.py or socket /var/run/dpdk/rte/dpdk_telemetry.v2\n");

    return 0;
}

void dpdk_telemetry_cleanup(void)
{
    // DPDK telemetry cleanup is handled by EAL
    RTE_LOG(INFO, L1TEL, "DPDK telemetry cleanup\n");
}
