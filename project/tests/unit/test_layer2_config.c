/* Layer-2 config round-trip test (pure C, no DPDK).
 *
 * Guards the parse <-> serialize symmetry for the ensemble-rule / conformal fields
 * (covers config parse + serialize round-trip). Regression target: load ->
 * set ensemble_rule=1 -> save -> reload must NOT silently revert to OR. Also
 * checks the default is OR (the shipped/published default).
 */
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include "layer2/config/layer2_config.h"

int main(void) {
    /* 1. Defaults: shipped default is disjunctive OR, capacity 4096 (>= 3/alpha). */
    struct layer2_config c;
    layer2_config_init_defaults(&c);
    assert(c.ensemble_rule == L2_ENSEMBLE_RULE_OR);
    assert(c.conformal_capacity == L2_DEFAULT_CONFORMAL_CAPACITY);
    assert(c.conformal_capacity == 4096);

    /* 2. Operator selects conformal Bonferroni + non-default params. */
    c.ensemble_rule    = L2_ENSEMBLE_RULE_CONFORMAL_BONF;
    c.conformal_alpha  = 0.002;
    c.routed_fdr_alpha = 0.05;
    c.conformal_capacity = 8192;

    /* 3. Round-trip: save -> reload. A prior bug (serialize omitted these fields) would
     *    drop them, reverting ensemble_rule to OR on reload. */
    const char *path = "/tmp/test_layer2_config_rt.json";
    assert(layer2_config_save(&c, path) == 0);

    struct layer2_config d;
    layer2_config_init_defaults(&d);
    assert(layer2_config_load(&d, path) == 0);

    assert(d.ensemble_rule == L2_ENSEMBLE_RULE_CONFORMAL_BONF);  /* the round-trip assertion */
    assert(d.conformal_alpha == 0.002);
    assert(d.routed_fdr_alpha == 0.05);
    assert(d.conformal_capacity == 8192);

    /* 4. Out-of-range ensemble_rule must fall back to OR (parse range-check). */
    struct layer2_config e;
    layer2_config_init_defaults(&e);
    e.ensemble_rule = 99;
    assert(layer2_config_save(&e, path) == 0);
    struct layer2_config f;
    layer2_config_init_defaults(&f);
    assert(layer2_config_load(&f, path) == 0);
    assert(f.ensemble_rule == L2_ENSEMBLE_RULE_OR);

    unlink(path);
    printf("test_layer2_config: round-trip + range-check OK\n");
    return 0;
}
