"""Unit test for litnet_loader.load_litnet_per_subnet -- verifies the headline
L1-mechanism invariant the runner is supposed to reproduce:

    For one source B sending one packet to each of N destinations within a /24
    in the same second, the L1 mechanism reads unique_src_ips = 1 (a true union
    over the subnet's source IPs), not unique_src_ips ~= N (the L2-zone post-hoc
    sum of per-(dst_ip, sec) HLLs).

The 85-column LITNET CSV layout is reconstructed in a small in-memory fixture
so this test runs without the 23 GB dataset on disk. Asserts:

  1. one source x N destinations within a single /24 second -> unique_src_ips = 1
  2. M distinct sources x N destinations within a single /24 second -> unique_src_ips = M
  3. Flows to different /24 subnets in the same second produce separate
     per-(subnet, second) accumulators (no cross-subnet contamination).
  4. The /16 grouping correctly folds multiple /24s into one subnet.

Failure of any of these assertions means the L1 vs L2-zone comparison in the
paper section 6.1.5 is meaningless. Each invariant is exactly what
ip_protected_subnet_add + l1_resolve_track_key produce at the data plane
(layer1/tables/ip_lists.c:626-682, layer1/layer1.c:1925-1932).
"""
import os, sys, tempfile, csv

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
# Locate the experiment package whether we're in the source tree
# (<repo>/experiment, tests at <repo>/tests/unit_python/) or the GitHub-release
# tree (<root>/experiments, tests at <root>/project/tests/unit_python/).
for _candidate in (
    os.path.join(THIS_DIR, "..", "..", "ComparisonResults"),
    os.path.join(THIS_DIR, "..", "..", "..", "ComparisonResults"),
    os.path.join(THIS_DIR, "..", "..", "experiment"),
    os.path.join(THIS_DIR, "..", "..", "experiments"),
    os.path.join(THIS_DIR, "..", "..", "..", "experiment"),
    os.path.join(THIS_DIR, "..", "..", "..", "experiments"),
    os.path.join(os.environ.get("ANTIDDOS_BASE", ""), "ComparisonResults"),
    os.path.join(os.environ.get("ANTIDDOS_BASE", ""), "experiment"),
    os.path.join(os.environ.get("ANTIDDOS_BASE", ""), "experiments"),
):
    _candidate = os.path.abspath(_candidate)
    if os.path.isdir(_candidate):
        sys.path.insert(0, _candidate)
        break
else:
    raise RuntimeError("could not locate ComparisonResults or experiment package "
                       "from {}".format(THIS_DIR))

from litnet_loader import load_litnet_per_subnet, _subnet_for  # noqa: E402


# LITNET CSV has 85 columns. We populate the indices the loader reads
# (litnet_loader.py C_* constants) and zero everything else.
LITNET_NCOLS = 85
C_TS = (1, 2, 3, 4, 5, 6)
C_TD, C_SA, C_DA, C_SP, C_DP, C_PR = 13, 14, 15, 16, 17, 18
C_IPKT, C_IBYT, C_OPKT, C_OBYT = 27, 28, 29, 30
C_ATTACK_T, C_ATTACK_A = 83, 84


def _make_row(ts, src_ip, dst_ip, dst_port=80, proto='TCP', ipkt=1, ibyt=64,
              opkt=0, obyt=0, td=0.0, attack=False, attack_type='none'):
    """Build one LITNET-shaped CSV row. ts is a (Y, mo, d, h, mi, s) tuple."""
    row = [''] * LITNET_NCOLS
    row[0] = '0'
    row[C_TS[0]] = str(ts[0]); row[C_TS[1]] = str(ts[1]); row[C_TS[2]] = str(ts[2])
    row[C_TS[3]] = str(ts[3]); row[C_TS[4]] = str(ts[4]); row[C_TS[5]] = str(ts[5])
    row[C_TD] = str(td)
    row[C_SA] = src_ip; row[C_DA] = dst_ip
    row[C_SP] = '12345'; row[C_DP] = str(dst_port)
    row[C_PR] = proto
    row[C_IPKT] = str(ipkt); row[C_IBYT] = str(ibyt)
    row[C_OPKT] = str(opkt); row[C_OBYT] = str(obyt)
    row[C_ATTACK_T] = attack_type
    row[C_ATTACK_A] = '1' if attack else '0'
    return row


def _write_part_dir(rows):
    """Write `rows` to a temp dir as one allFlows_part_*.csv, return dir path."""
    d = tempfile.mkdtemp(prefix='litnet_test_')
    path = os.path.join(d, 'allFlows_part_00.csv')
    with open(path, 'w', newline='') as fh:
        w = csv.writer(fh)
        w.writerow(['col_%d' % i for i in range(LITNET_NCOLS)])  # header
        for r in rows:
            w.writerow(r)
    return d


def test_subnet_for_helper():
    """Sanity-check the IPv4 -> /prefix subnet-network helper."""
    assert _subnet_for('193.219.165.4', 24) == '193.219.165.0/24'
    assert _subnet_for('193.219.165.4', 16) == '193.219.0.0/16'
    assert _subnet_for('193.219.165.4', 32) == '193.219.165.4/32'
    assert _subnet_for('1.2.3.255', 24) == '1.2.3.0/24'
    assert _subnet_for('1.2.4.0', 24) == '1.2.4.0/24'
    assert _subnet_for('not.an.ipv4', 24) is None
    print('  test_subnet_for_helper ✓')


def test_carpet_bomb_invariant():
    """One source x 256 destinations within a /24, one second -> unique_src_ips = 1.

    This is the carpet-bomb invariant the L1 mechanism preserves: the L2-zone
    post-hoc sum would read unique_src_ips ~= 256 for the same traffic (sum of
    256 per-destination HLLs each seeing {B}); the L1 true-union reads 1.
    """
    ts = (2020, 1, 25, 12, 0, 0)
    src = '10.0.0.5'
    rows = [_make_row(ts, src_ip=src, dst_ip=f'193.219.165.{i}')
            for i in range(256)]
    parts_dir = _write_part_dir(rows)
    result = load_litnet_per_subnet(parts_dir, prefix_bits=24,
                                     keep_prefixes=('193.219.',),
                                     min_windows=1, progress_every=0)
    assert '193.219.165.0/24' in result, \
        f"expected /24 subnet key in result, got keys: {list(result)}"
    windows = result['193.219.165.0/24']
    assert len(windows) == 1, f"expected 1 second-window, got {len(windows)}"
    w = windows[0]
    # THE INVARIANT under test:
    assert w['unique_src_ips'] == 1.0, \
        f"L1 invariant violated: 1 source × 256 destinations should yield "\
        f"unique_src_ips = 1 (true union), got {w['unique_src_ips']}"
    assert w['unique_dst_ips'] == 256.0, \
        f"expected unique_dst_ips = 256 (the 256 distinct destinations), got {w['unique_dst_ips']}"
    print('  test_carpet_bomb_invariant ✓  (1 source × 256 destinations → unique_src_ips = 1)')


def test_multiple_sources_one_subnet():
    """M distinct sources x N destinations within a /24 second -> unique_src_ips = M."""
    ts = (2020, 1, 25, 12, 0, 0)
    sources = [f'10.0.0.{i}' for i in range(5)]    # 5 sources
    dests = [f'83.171.20.{i}' for i in range(10)]  # 10 destinations
    rows = [_make_row(ts, src_ip=s, dst_ip=d) for s in sources for d in dests]
    parts_dir = _write_part_dir(rows)
    result = load_litnet_per_subnet(parts_dir, prefix_bits=24,
                                     keep_prefixes=('83.171.',),
                                     min_windows=1, progress_every=0)
    assert '83.171.20.0/24' in result
    windows = result['83.171.20.0/24']
    w = windows[0]
    assert w['unique_src_ips'] == 5.0, \
        f"expected unique_src_ips = 5, got {w['unique_src_ips']}"
    assert w['unique_dst_ips'] == 10.0
    print('  test_multiple_sources_one_subnet ✓  (5 sources × 10 destinations → unique_src_ips = 5)')


def test_subnets_are_isolated():
    """Two carpet-bombs to different /24s in the same second produce two
    separate per-(subnet, second) accumulators -- no cross-subnet leakage."""
    ts = (2020, 1, 25, 12, 0, 0)
    # Carpet-bomb 1: src A -> 193.219.165.0/24
    rows = [_make_row(ts, src_ip='10.0.0.1', dst_ip=f'193.219.165.{i}')
            for i in range(100)]
    # Carpet-bomb 2: src B -> 83.171.20.0/24 (different subnet, same second)
    rows += [_make_row(ts, src_ip='10.0.0.2', dst_ip=f'83.171.20.{i}')
             for i in range(50)]
    parts_dir = _write_part_dir(rows)
    result = load_litnet_per_subnet(parts_dir, prefix_bits=24,
                                     keep_prefixes=('193.219.', '83.171.'),
                                     min_windows=1, progress_every=0)
    assert '193.219.165.0/24' in result
    assert '83.171.20.0/24' in result
    w1 = result['193.219.165.0/24'][0]
    w2 = result['83.171.20.0/24'][0]
    # Each subnet sees only its own source; no leakage
    assert w1['unique_src_ips'] == 1.0  # only 10.0.0.1
    assert w1['unique_dst_ips'] == 100.0
    assert w2['unique_src_ips'] == 1.0  # only 10.0.0.2
    assert w2['unique_dst_ips'] == 50.0
    print('  test_subnets_are_isolated ✓  (two simultaneous /24 carpet-bombs do not contaminate each other)')


def test_slash_16_folds_distinct_24s():
    """Folding into a /16 unions sources across multiple /24 child subnets."""
    ts = (2020, 1, 25, 12, 0, 0)
    # Two different /24s within the same /16, hit by two different sources
    rows  = [_make_row(ts, src_ip='10.0.0.1', dst_ip=f'193.219.10.{i}')   for i in range(50)]
    rows += [_make_row(ts, src_ip='10.0.0.2', dst_ip=f'193.219.20.{i}')   for i in range(50)]
    parts_dir = _write_part_dir(rows)
    result = load_litnet_per_subnet(parts_dir, prefix_bits=16,
                                     keep_prefixes=('193.219.',),
                                     min_windows=1, progress_every=0)
    assert '193.219.0.0/16' in result, f"got keys: {list(result)}"
    w = result['193.219.0.0/16'][0]
    # Both sources are unioned at the /16 level
    assert w['unique_src_ips'] == 2.0, \
        f"expected /16 to union 2 sources across child /24s, got {w['unique_src_ips']}"
    # And both destination-sets are unioned
    assert w['unique_dst_ips'] == 100.0
    print('  test_slash_16_folds_distinct_24s ✓  (/16 unions sources across multiple /24 children)')


if __name__ == '__main__':
    print('=== test_l1_subnet_loader.py ===')
    test_subnet_for_helper()
    test_carpet_bomb_invariant()
    test_multiple_sources_one_subnet()
    test_subnets_are_isolated()
    test_slash_16_folds_distinct_24s()
    print('All 5 invariants verified — L1 loader is faithful to the true-union HLL semantic.')
