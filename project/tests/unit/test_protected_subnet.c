/**
 * test_protected_subnet.c -- protected-subnet (CIDR) aggregation in Layer 1.
 *
 * Verifies the building blocks of the "carpet-bomb across a /24" fix:
 *   1. ip_protected_subnet_add/lookup/remove/count + prefix masking.
 *   2. The Stage-3c keying rule (replicated below as resolve_track_slot()):
 *      an exact protected /32 keeps its own per-IP slot; any other address in a
 *      protected subnet is aggregated into the subnet's single slot -- so many
 *      distinct destinations in the /24 fold into one tracked entry, which is
 *      exactly what lets Layer 2 see a distributed flood that no single IP trips.
 *   3. New flows (Stage 11) are counted on the slot Stage 3c tracks, through the
 *      production per_ip_features_lookup_track(), so a subnet slot's
 *      flows_per_sec counts the new flows of every address it aggregates.
 *
 * Needs EAL (rte_lpm / per_ip_features hash), mirroring test_flow_table.c.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>

#include <rte_eal.h>
#include <rte_byteorder.h>
#include <rte_lcore.h>

#include "../../layer1/tables/ip_lists.h"
#include "../../layer1/telemetry/per_ip_features.h"

#define HOST_IP(a, b, c, d) \
    (((uint32_t)(a) << 24) | ((uint32_t)(b) << 16) | ((uint32_t)(c) << 8) | (uint32_t)(d))
#define BE_IP(a, b, c, d) rte_cpu_to_be_32(HOST_IP(a, b, c, d))

/* Exactly the Layer 1 Stage-3c flow, calling the SAME production policy function
 * (l1_resolve_track_key) rather than a replica, so the test tracks production. */
static struct per_ip_features *resolve_track_slot(uint32_t dst_ip_be) {
    struct per_ip_features *exact = per_ip_features_lookup(dst_ip_be);
    uint32_t net_be = 0;
    bool in_subnet = (!exact && ip_protected_subnet_count() > 0 &&
                      ip_protected_subnet_lookup(dst_ip_be, &net_be));
    uint32_t key = l1_resolve_track_key(dst_ip_be, exact != NULL, in_subnet, net_be);
    return exact ? exact : (in_subnet ? per_ip_features_lookup(key) : NULL);
}

int main(int argc, char **argv) {
    (void)argc;

    /* Pure policy checks for l1_resolve_track_key() -- no EAL required. */
    assert(l1_resolve_track_key(BE_IP(10, 0, 5, 10), true, false, 0) == BE_IP(10, 0, 5, 10));
    assert(l1_resolve_track_key(BE_IP(10, 0, 5, 10), false, true, BE_IP(10, 0, 5, 0))
           == BE_IP(10, 0, 5, 0));
    assert(l1_resolve_track_key(BE_IP(10, 0, 6, 5), false, false, 0) == BE_IP(10, 0, 6, 5));
    printf("pure policy: exact wins, subnet maps to network, no-match -> self\n");

    /* No shared files (--in-memory is refused with --no-huge); argc is counted from the array. */
    char *eal_args[] = { argv[0], "-l", "0", "-n", "1", "--no-huge", "--no-pci", "-m", "256", "--no-shconf", "--no-telemetry", NULL };
    if (rte_eal_init((int)RTE_DIM(eal_args) - 1, eal_args) < 0) {
        fprintf(stderr, "EAL init failed (missing DPDK permissions / runtime directory) -- skipping test\n");
        return 77;
    }

    struct ip_lists_config cfg = {
        .max_whitelist_entries = 1024,
        .max_blacklist_entries = 1024,
        .max_protected_entries = 1024,
        .max_whitelist_cidrs = 64,
        .enforce_protected_ips = false,
    };
    assert(ip_lists_init(&cfg) == 0);
    assert(per_ip_features_init(64) == 0);

    /* 1. Register a /24 and check the count + masking idempotence. */
    assert(ip_protected_subnet_add(HOST_IP(10, 0, 5, 0), 24) == 0);
    assert(ip_protected_subnet_count() == 1);
    /* Adding a host inside the same /24 normalizes to the same network -> no-op. */
    assert(ip_protected_subnet_add(HOST_IP(10, 0, 5, 7), 24) == 0);
    assert(ip_protected_subnet_count() == 1);

    /* 2. Lookup: inside hits and returns the network; outside misses. */
    uint32_t net_be = 0;
    assert(ip_protected_subnet_lookup(BE_IP(10, 0, 5, 99), &net_be) == true);
    assert(net_be == BE_IP(10, 0, 5, 0));
    assert(ip_protected_subnet_lookup(BE_IP(10, 0, 6, 1), &net_be) == false);

    /* 3. Aggregation: distinct addresses in the /24 fold into ONE slot. */
    struct per_ip_features *s_a = resolve_track_slot(BE_IP(10, 0, 5, 10));
    struct per_ip_features *s_b = resolve_track_slot(BE_IP(10, 0, 5, 200));
    assert(s_a != NULL && s_b != NULL && s_a == s_b);
    /* An address outside the subnet is not tracked. */
    assert(resolve_track_slot(BE_IP(10, 0, 6, 5)) == NULL);
    printf("aggregation: 10.0.5.10 and 10.0.5.200 share one slot, 10.0.6.5 untracked\n");

    /* 4. Exact /32 wins over the covering subnet (longest prefix). */
    assert(ip_protected_add(BE_IP(10, 0, 5, 10)) == 0);
    struct per_ip_features *s_exact = resolve_track_slot(BE_IP(10, 0, 5, 10));
    assert(s_exact != NULL && s_exact != s_a);          /* its own slot, not the subnet's */
    assert(resolve_track_slot(BE_IP(10, 0, 5, 11)) == s_a);  /* others still aggregate */
    printf("exact /32 10.0.5.10 keeps its own slot; 10.0.5.11 still aggregates\n");

    /* 5. Remove the subnet: lookups miss, count drops. */
    assert(ip_protected_subnet_remove(HOST_IP(10, 0, 5, 0), 24) == 0);
    assert(ip_protected_subnet_count() == 0);
    assert(ip_protected_subnet_lookup(BE_IP(10, 0, 5, 99), &net_be) == false);
    /* The exact /32 is unaffected by removing the subnet. */
    assert(resolve_track_slot(BE_IP(10, 0, 5, 10)) == s_exact);

    /* 6. Top-talker export selection: when more IPs are registered than fit the
     *    export window, the busiest (by this-window volume) must be selected,
     *    not an arbitrary hash-order subset. Register 6 IPs with volumes 1..6;
     *    export only 3 -> must return the three busiest (10.1.0.{4,5,6}). */
    const unsigned lcore = rte_lcore_id();
    for (int j = 1; j <= 6; j++) {
        uint32_t be = BE_IP(10, 1, 0, j);
        assert(per_ip_features_register(be) == 0);
        struct per_ip_features *p = per_ip_features_lookup(be);
        assert(p != NULL);
        for (int n = 0; n < j; n++)
            per_ip_features_update_counters(p, lcore, 6 /*TCP*/, 0x02 /*SYN*/, 64, false);
    }
    struct per_ip_feature_snapshot snaps[8];
    uint32_t got = per_ip_features_snapshot_all(snaps, 3);  /* >3 registered -> selection */
    assert(got == 3 && "selection returns exactly max_count");
    bool s4 = false, s5 = false, s6 = false, low = false;
    for (uint32_t i = 0; i < got; i++) {
        if (snaps[i].dst_ip == BE_IP(10, 1, 0, 6)) s6 = true;
        else if (snaps[i].dst_ip == BE_IP(10, 1, 0, 5)) s5 = true;
        else if (snaps[i].dst_ip == BE_IP(10, 1, 0, 4)) s4 = true;
        else low = true;  /* any lower-volume entry (j<=3, or the 0-volume exact /32) */
    }
    assert(s4 && s5 && s6 && !low && "export must pick the 3 busiest, not arbitrary");
    printf("top-talker export: 3 busiest of 7 registered selected (10.1.0.{4,5,6})\n");

    /* 7. New flows count on the slot Stage 3c tracks. layer1.c resolves both the
     *    Stage 3c slot and the Stage 11 new_flows slot with
     *    per_ip_features_lookup_track(), which must match the Stage-3c flow above;
     *    new flows to addresses covered only by a protected subnet must then reach
     *    the subnet slot's flows_per_sec. */
    assert(ip_protected_subnet_add(HOST_IP(10, 0, 7, 0), 24) == 0);
    assert(ip_protected_add(BE_IP(10, 0, 7, 50)) == 0);   /* exact /32 inside the /24 */
    const uint32_t probes[] = {
        BE_IP(10, 0, 7, 1), BE_IP(10, 0, 7, 50), BE_IP(10, 0, 7, 255),  /* subnet, exact, subnet */
        BE_IP(10, 0, 8, 1), BE_IP(10, 0, 5, 99),                        /* untracked */
        BE_IP(10, 0, 5, 10), BE_IP(10, 1, 0, 6),                        /* exact elsewhere */
    };
    for (size_t i = 0; i < sizeof(probes) / sizeof(probes[0]); i++) {
        assert(per_ip_features_lookup_track(probes[i]) == resolve_track_slot(probes[i]) &&
               "the production lookup must resolve like Stage 3c");
    }
    struct per_ip_features *s_net = per_ip_features_lookup(BE_IP(10, 0, 7, 0));
    struct per_ip_features *s_x50 = per_ip_features_lookup(BE_IP(10, 0, 7, 50));
    assert(s_net != NULL && s_x50 != NULL && s_net != s_x50);
    assert(per_ip_features_lookup_track(BE_IP(10, 0, 7, 99)) == s_net);
    assert(per_ip_features_lookup_track(BE_IP(10, 0, 7, 50)) == s_x50);

    /* Stage 11, once per created flow: 40 to distinct addresses in the /24, one to
     * the exact /32, one to an untracked address (a NULL slot, ignored). */
    const uint32_t new_flows_subnet = 40;
    for (uint32_t i = 0; i < new_flows_subnet; i++) {
        uint32_t dst = rte_cpu_to_be_32(HOST_IP(10, 0, 7, 100 + i));
        per_ip_increment_new_flow(per_ip_features_lookup_track(dst), lcore);
    }
    per_ip_increment_new_flow(per_ip_features_lookup_track(BE_IP(10, 0, 7, 50)), lcore);
    per_ip_increment_new_flow(per_ip_features_lookup_track(BE_IP(10, 0, 8, 1)), lcore);

    /* Fresh slots have no previous window, so the snapshot uses 1 s and
     * flows_per_sec equals the new flows counted. */
    struct per_ip_feature_snapshot snap_net, snap_x50;
    assert(per_ip_features_snapshot(BE_IP(10, 0, 7, 0), &snap_net) == 0);
    assert(per_ip_features_snapshot(BE_IP(10, 0, 7, 50), &snap_x50) == 0);
    printf("new flows: subnet 10.0.7.0/24 flows_per_sec=%u (expected %u), "
           "exact 10.0.7.50 flows_per_sec=%u (expected 1)\n",
           snap_net.flows_per_sec, new_flows_subnet, snap_x50.flows_per_sec);
    fflush(stdout);  /* keep the values if an assert aborts */
    assert(snap_net.flows_per_sec == new_flows_subnet &&
           "new flows to subnet-covered addresses must count on the subnet slot");
    assert(snap_x50.flows_per_sec == 1 && "the exact /32 keeps its own new flow");
    printf("new-flow counting: Stage 11 uses the Stage 3c slot (subnet and exact /32)\n");

    printf("\nPASS: protected-subnet aggregation, exact-/32 precedence, masking, "
           "and top-talker export selection all hold.\n");
    return 0;
}
