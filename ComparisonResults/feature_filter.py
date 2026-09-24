"""Per-dataset feature-set filter.

Given a list of candidate features and a sample of windows from a cache, returns
the subset whose values have non-zero variance (and pass an effectively-all-zero
threshold). Used by each runner to auto-exclude features that are inert in
their specific dataset.

Why per-dataset and per-runtime: different datasets have different baselines
(IoT traffic has no IPv6, no fragmentation; CIC-DDoS2019 has TCP handshakes;
LITNET has no TCP flags at all). Hard-coding a feature list per dataset is
brittle; computing it at runtime from the cache is robust.

Background -- the canonical 39-feature production set (see `layer2/baselines.h`
L2_MAX_FEATURES enum) is `PRODUCTION_39_FEATURES` below. `flow_duration_avg`
is a known extractor placeholder (always 0.0 in pcap caches because the
offline extractor does not track flow lifetimes); `heavy_hitter_count` is a
CMS-stub that returns non-zero counts on real attacks but degenerates to 0
on benign windows in some caches. Both are filtered out automatically when
inert; the production C path computes both correctly.

`burst_factor` and `unique_flows` are removed from the list below: they are
placeholders of the offline extractor (burst_factor = packets_per_sec,
unique_flows = flows_per_sec), see Supplementary S10. The name is kept for
continuity; the list now holds 37 names.
"""

PRODUCTION_39_FEATURES = [
    'packets_per_sec', 'bytes_per_sec', 'flows_per_sec',
    'syn_per_sec', 'syn_ack_per_sec', 'ack_per_sec', 'rst_per_sec', 'fin_per_sec',
    'tcp_ratio', 'udp_ratio', 'icmp_ratio', 'other_ratio',
    'syn_ack_ratio', 'rst_syn_ratio', 'bytes_per_packet',
    'unique_src_ips', 'unique_dst_ports',
    'new_srcip_rate',
    'max_flow_fraction', 'topk_flow_share', 'heavy_hitter_count',
    'avg_packets_per_flow', 'flow_duration_avg',
    'syn_tcp_ratio', 'synack_tcp_ratio', 'ack_tcp_ratio', 'rst_tcp_ratio', 'fin_tcp_ratio',
    'udp_flow_ratio', 'icmp_echo_ratio',
    'dst_port_density',
    'src_ip_entropy', 'src_port_entropy',
    'small_pkt_ratio', 'fragment_ratio', 'ttl_mean',
    'tcp_completion_rate',
]


def filter_active(candidate_features, sample_rows,
                  min_variance=1e-9, min_nonzero_frac=0.001):
    """Returns (active, inert) feature lists.

    A feature is INERT if either:
      - max - min < min_variance over the sample (zero variance)
      - nonzero_count / len(sample) < min_nonzero_frac (effectively all-zero)

    Args:
        candidate_features: list of feature names to test.
        sample_rows: list of window dicts (each row should have the feature
            as a key -- missing keys are treated as feature-not-present).
        min_variance: features with max-min below this are inert (default 1e-9).
        min_nonzero_frac: features with nonzero rate below this are inert
            (default 0.001 -- needs at least 0.1% nonzero in sample).
    """
    active, inert = [], []
    n = max(len(sample_rows), 1)
    for f in candidate_features:
        vals = [r.get(f) for r in sample_rows if r.get(f) is not None]
        if not vals:
            inert.append(f); continue
        vmin, vmax = min(vals), max(vals)
        nonzero = sum(1 for v in vals if v != 0)
        if (vmax - vmin) < min_variance or nonzero / n < min_nonzero_frac:
            inert.append(f)
        else:
            active.append(f)
    return active, inert


def _smoke():
    """Smoke test -- exercises both active and inert paths."""
    rows = [
        {'a': 1.0, 'b': 0.0, 'c': None, 'd': 5.0, 'e': 1e-12, 'f': 0.0},
        {'a': 2.0, 'b': 0.0, 'c': 3.0, 'd': 5.0, 'e': 1e-12, 'f': 0.5},
        {'a': 3.0, 'b': 0.0, 'c': 4.0, 'd': 5.0, 'e': 2e-12, 'f': 0.0},
    ]
    active, inert = filter_active(['a', 'b', 'c', 'd', 'e', 'f', 'missing'], rows)
    # 'a' varies -> active; 'b' all zero -> inert; 'c' has only 2 nonzero of 3 -> active
    # 'd' constant 5 -> inert (max-min == 0); 'e' tiny variance below 1e-9 -> inert
    # 'f' has 1 nonzero of 3 (33%) -> active; 'missing' has no values -> inert
    assert active == ['a', 'c', 'f'], f"got {active}"
    assert inert == ['b', 'd', 'e', 'missing'], f"got {inert}"

    # Stronger min_nonzero_frac filter excludes 'f' (only 33% nonzero vs 80% threshold)
    active2, inert2 = filter_active(['a', 'f'], rows, min_nonzero_frac=0.8)
    assert active2 == ['a'], f"got {active2}"
    assert 'f' in inert2

    print("feature_filter smoke OK")


if __name__ == '__main__':
    _smoke()
