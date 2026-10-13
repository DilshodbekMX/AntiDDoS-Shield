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

    char *eal_args[] = { argv[0], "-l", "0", "-n", "1", "--no-huge", "--no-pci", "-m", "256", "--in-memory", NULL };
    if (rte_eal_init(9, eal_args) < 0) {
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

    printf("\nPASS: protected-subnet aggregation, exact-/32 precedence, masking, "
           "and top-talker export selection all hold.\n");
    return 0;
}
