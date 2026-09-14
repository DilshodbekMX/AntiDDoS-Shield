"""
LITNET-2020 L1-semantic protected-subnet evaluation.

This runner reproduces the L1 protected-subnet aggregation mechanism
(`ip_protected_subnet_add` + Stage-3c keying `l1_resolve_track_key` at
`layer1/layer1.c:1925-1932`) at the offline harness level. Unlike
`run_litnet_zone.py`, which post-hoc sums per-(dst_ip, second) HLL counts (an
L2-zone semantic -- recall-biased upper bound), this runner streams flows
through `litnet_loader.load_litnet_per_subnet` and produces one accumulator
per (subnet, second) whose `unique_src_ips` is the TRUE UNION of source IPs
across every destination in the subnet during that second -- matching the
single HLL at the L1 data-plane slot.

Carpet-bomb invariant the L1 semantic preserves:
    For one source B sending one packet to each of N destinations in
    /prefix_bits within one second:
      - L1 (this runner): unique_src_ips = 1
      - L2 zone (run_litnet_zone): unique_src_ips ~= N

After streaming the flows once per prefix_bits choice, per-subnet rows are
evaluated by the same per-IP detector pipeline used in run_litnet.py: 60/20/20
benign split, three-tier EWMA + CUSUM + JSD + LogZ ensemble, calibrated theta and
fixed-theta=4.0 passes, conjunction baseline-update gate. Per-attack DR is
aggregated across victim subnets (>=30 attack windows), uninvolved-subnet FPR
across subnets with zero attack windows.

Quantifies what the L1 mechanism actually catches at LITNET scale, alongside
the L2-zone numbers run_litnet_zone reports.

Outputs: litnet_l1subnet_24_results.json and litnet_l1subnet_16_results.json
"""
import sys, os, json, time, copy
from collections import Counter
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
# modules live one level up, in ComparisonResults/
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')))

from config import *
from litnet_loader import load_litnet_per_subnet
from baselines import ThreeTierBaseline
from detectors import CUSUMDetector, LogZDetector, JSDDetector
from pipeline import detect_row, calibrate_threshold, calibrate_cusum_h, wilson_ci

LITNET_DIR = os.environ.get(
    "LITNET_DIR",
    os.path.join(BASE, "datasets", "LITNET-2020", "parts"),
)

# Auto-filtered at runtime against PRODUCTION_39_FEATURES ∪
# {unique_dst_ips}. dir_ratio and ttl_mean are zero-variance from the loader
# (no opkt, no TTL); unique_dst_ips DOES have variance here unlike the per-IP
# runner because subnet aggregation pools multiple destinations into one
# (subnet, sec) row -- the value is the count of distinct dst_ips in that
# subnet during that second.
from feature_filter import filter_active, PRODUCTION_39_FEATURES
LITNET_FEATURES = []  # populated in evaluate() once the first subnet's rows load

# Protected internal ranges only -- the 1-IP external victim (23.32.104.60)
# does not produce a meaningful subnet aggregation by itself and is omitted
# here so the comparison to run_litnet_zone is interpretable.
KEEP_PREFIXES = ('193.219.', '83.171.')

MIN_WINDOWS_PER_SUBNET = 100
MIN_ATTACK_WINDOWS_FOR_DR = 30

# CACHE_DIR comes from config.py (this package's cache/).
# RESULTS_DIR comes from config.py, anchored to this package's own directory.
# (Previously hardcoded to BASE/experiment/results, which wrote into a different tree.)
def cache_path_for(prefix_bits):
    return os.path.join(CACHE_DIR, f"litnet_l1subnet_{prefix_bits}_cache.json")


def output_path_for(prefix_bits):
    return os.path.join(RESULTS_DIR, f"litnet_l1subnet_{prefix_bits}_results.json")


def load_per_subnet(prefix_bits, use_cache=True):
    cache = cache_path_for(prefix_bits)
    if use_cache and os.path.exists(cache):
        print(f"  Loading cached /{prefix_bits} subnet windows: {cache}")
        from datetime import datetime
        with open(cache) as f:
            data = json.load(f)
        for sn, rows in data.items():
            for w in rows:
                w['_dt'] = datetime.fromisoformat(w['_dt'])
        return data

    print(f"  Streaming + L1-aggregating per /{prefix_bits} subnet from {LITNET_DIR} ...")
    t0 = time.time()
    per_subnet = load_litnet_per_subnet(
        LITNET_DIR, prefix_bits=prefix_bits, window_sec=1,
        min_windows=MIN_WINDOWS_PER_SUBNET,
        keep_prefixes=KEEP_PREFIXES,
    )
    print(f"    {len(per_subnet)} subnets (>= {MIN_WINDOWS_PER_SUBNET} windows) "
          f"in {time.time() - t0:.1f}s")

    # Serialize to cache
    ser = {}
    for sn, rows in per_subnet.items():
        ser[sn] = [{**w, '_dt': w['_dt'].isoformat()} for w in rows]
    os.makedirs(CACHE_DIR, exist_ok=True)
    with open(cache, 'w') as f:
        json.dump(ser, f)
    print(f"    Cached to {cache} ({os.path.getsize(cache) / 1e6:.1f} MB)")
    return per_subnet


def evaluate_subnet(rows):
    """Per-subnet eval -- structurally identical to run_litnet.evaluate_ip but the
    rows now have L1-semantic unique_src_ips (true union over subnet sources)."""
    rows = sorted(rows, key=lambda r: r['_dt'])
    benign = [r for r in rows if not r['_is_attack']]
    attack = [r for r in rows if r['_is_attack']]
    if len(benign) < 50:
        return None

    n_tr = int(len(benign) * 0.60)
    n_ca = int(len(benign) * 0.20)
    train_w = benign[:n_tr]
    calib_w = benign[n_tr:n_tr + n_ca]
    benign_test = benign[n_tr + n_ca:]
    test_w = list(benign_test) + list(attack)
    if len(train_w) < 30 or not test_w:
        return None

    bl = ThreeTierBaseline(LITNET_FEATURES)
    for r in train_w:
        bl.update(r, r['_dt'])
    cusum = CUSUMDetector(LITNET_FEATURES)
    logz = LogZDetector(LITNET_FEATURES)
    jsd_d = JSDDetector()
    for r in train_w:
        cusum.update(r, bl, r['_dt']); logz.update(r, THETA_INIT); jsd_d.update_and_check(r)
    for f in cusum.s_high:
        cusum.s_high[f] = 0.0; cusum.s_low[f] = 0.0

    theta = calibrate_threshold(calib_w, bl) if len(calib_w) >= 5 else THETA_INIT
    h_mult = calibrate_cusum_h(calib_w, bl, cusum) if len(calib_w) >= 5 else CUSUM_H_MULT
    cusum.h_mult = h_mult
    for r in calib_w:
        bl.update(r, r['_dt'])
    for f in cusum.s_high:
        cusum.s_high[f] = 0.0; cusum.s_low[f] = 0.0

    bl_p = copy.deepcopy(bl)
    cusum_p = copy.deepcopy(cusum); cusum_p.h_mult = CUSUM_H_MULT
    logz_p = copy.deepcopy(logz); jsd_p = copy.deepcopy(jsd_d)

    tp = fp = fn = tn = 0
    tp_p = fp_p = fn_p = tn_p = 0
    per_type = {}
    per_type_p = {}
    for r in test_w:
        is_atk = r['_is_attack']
        det, _, _, _ = detect_row(r, bl, cusum, logz, jsd_d, theta, r['_dt'])
        if is_atk and det: tp += 1
        elif is_atk and not det: fn += 1
        elif not is_atk and det: fp += 1
        else: tn += 1
        if is_atk:
            t = r['_attack_type']
            d = per_type.setdefault(t, {'tp': 0, 'n': 0})
            d['n'] += 1
            if det: d['tp'] += 1
        if not det and not is_atk:
            bl.update(r, r['_dt'])

        det_p, _, _, _ = detect_row(r, bl_p, cusum_p, logz_p, jsd_p, THETA_INIT, r['_dt'])
        if is_atk and det_p: tp_p += 1
        elif is_atk and not det_p: fn_p += 1
        elif not is_atk and det_p: fp_p += 1
        else: tn_p += 1
        if is_atk:
            t = r['_attack_type']
            d = per_type_p.setdefault(t, {'tp': 0, 'n': 0})
            d['n'] += 1
            if det_p: d['tp'] += 1
        if not det_p and not is_atk:
            bl_p.update(r, r['_dt'])

    return {'tp': tp, 'fp': fp, 'fn': fn, 'tn': tn,
            'tp_p': tp_p, 'fp_p': fp_p, 'fn_p': fn_p, 'tn_p': tn_p,
            'n_attack': tp + fn, 'n_benign': fp + tn,
            'theta': theta, 'per_type': per_type, 'per_type_p': per_type_p}


def _cluster_ci(units, nb=2000, seed=7):
    import random as _rnd
    if not units: return [0.0, 0.0]
    rng = _rnd.Random(seed); m = len(units); rates = []
    for _ in range(nb):
        fp = tot = 0
        for _ in range(m):
            a, b = units[rng.randrange(m)]; fp += a; tot += b
        if tot: rates.append(fp / tot * 100)
    rates.sort()
    return [round(rates[int(0.025*len(rates))], 1), round(rates[int(0.975*len(rates))], 1)]


def run_for_prefix(prefix_bits):
    print(f"\n=== LITNET-2020 L1-semantic /{prefix_bits} subnet evaluation ===")
    per_subnet = load_per_subnet(prefix_bits)
    print(f"  Evaluating {len(per_subnet)} subnets")

    # Auto-detect active features against PRODUCTION_39_FEATURES
    # ∪ {unique_dst_ips} on benign-period rows. NetFlow's 13-feature schema
    # leaves 26 features missing; dir_ratio + ttl_mean zero-variance; for the
    # subnet aggregation, unique_dst_ips DOES carry variance (multiple
    # destinations per subnet during attack windows). Persisted to metadata.
    sample = []
    for sn, rs in per_subnet.items():
        sample.extend([r for r in rs if not r.get('_is_attack')][:50])
        if len(sample) >= 5000:
            break
    if len(sample) < 500:
        sample = [r for sn, rs in per_subnet.items() for r in rs[:50]][:5000]
    candidate = list(PRODUCTION_39_FEATURES) + ['unique_dst_ips']
    new_active, new_inert = filter_active(candidate, sample)
    LITNET_FEATURES.clear(); LITNET_FEATURES.extend(new_active)
    globals()[f'_INERT_FEATURES_{prefix_bits}'] = new_inert
    print(f"  Feature filter (/{prefix_bits}): {len(LITNET_FEATURES)} active of "
          f"{len(candidate)} candidate; inert: {new_inert}")

    results = []
    agg_per_type = {}
    agg_per_type_p = {}
    for sn, rows in per_subnet.items():
        r = evaluate_subnet(rows)
        if r is None:
            continue
        r['subnet'] = sn
        results.append(r)
        for t, v in r['per_type'].items():
            a = agg_per_type.setdefault(t, {'tp': 0, 'n': 0})
            a['tp'] += v['tp']; a['n'] += v['n']
        for t, v in r.get('per_type_p', {}).items():
            a = agg_per_type_p.setdefault(t, {'tp': 0, 'n': 0})
            a['tp'] += v['tp']; a['n'] += v['n']

    if not results:
        print(f"  ERROR: no subnets evaluated at /{prefix_bits}")
        return None

    victims = [r for r in results if r['n_attack'] >= MIN_ATTACK_WINDOWS_FOR_DR]
    uninvolved = [r for r in results if r['n_attack'] == 0 and r['n_benign'] >= 30]

    v_tp = sum(r['tp'] for r in victims); v_fn = sum(r['fn'] for r in victims)
    v_dr = v_tp / max(v_tp + v_fn, 1) * 100
    v_ci = wilson_ci(v_tp, v_tp + v_fn)
    u_fp = sum(r['fp'] for r in uninvolved); u_tn = sum(r['tn'] for r in uninvolved)
    u_fpr = u_fp / max(u_fp + u_tn, 1) * 100
    u_ci = wilson_ci(u_fp, u_fp + u_tn)

    v_tp_p = sum(r['tp_p'] for r in victims); v_fn_p = sum(r['fn_p'] for r in victims)
    v_dr_p = v_tp_p / max(v_tp_p + v_fn_p, 1) * 100
    u_fp_p = sum(r['fp_p'] for r in uninvolved); u_tn_p = sum(r['tn_p'] for r in uninvolved)
    u_fpr_p = u_fp_p / max(u_fp_p + u_tn_p, 1) * 100

    u_fpr_cluster = _cluster_ci([(r['fp'], r['fp'] + r['tn']) for r in uninvolved])

    # Emit None for FPR fields when the denominator is empty -- a literal 0.0
    # with n_uninvolved=0 would mislead a reader skimming the JSON.
    has_uninvolved = bool(uninvolved) and (u_fp + u_tn) > 0
    u_fpr_out = round(u_fpr, 1) if has_uninvolved else None
    u_ci_out = [round(u_ci[0]*100, 1), round(u_ci[1]*100, 1)] if has_uninvolved else None
    u_cluster_out = u_fpr_cluster if has_uninvolved else None
    u_fpr_p_out = round(u_fpr_p, 1) if has_uninvolved else None

    print(f"  Victim subnets (>= {MIN_ATTACK_WINDOWS_FOR_DR} attack): {len(victims)}")
    print(f"  Uninvolved subnets (0 attack):          {len(uninvolved)}")
    print(f"  Aggregate DR on victim subnets:    {v_dr:.1f}% [{v_ci[0]*100:.1f}, {v_ci[1]*100:.1f}]  ({v_tp}/{v_tp+v_fn})")
    print(f"  Aggregate FPR on uninvolved:       {u_fpr:.1f}% [{u_ci[0]*100:.1f}, {u_ci[1]*100:.1f}] cluster-CI {u_fpr_cluster}")
    print(f"  --- fixed-θ=4.0 (production operating point) ---")
    print(f"  DR (fixed-θ):  {v_dr_p:.1f}%   FPR (fixed-θ): {u_fpr_p:.1f}%")

    print(f"\n  Per-attack-type DR (calib-θ / fixed-θ=4.0), across all victim subnets:")
    per_type_out = {}
    for t, v in sorted(agg_per_type.items(), key=lambda x: -x[1]['n']):
        dr = v['tp'] / max(v['n'], 1) * 100
        ci = wilson_ci(v['tp'], v['n'])
        vp = agg_per_type_p.get(t, {'tp': 0, 'n': 0})
        dr_p = vp['tp'] / max(vp['n'], 1) * 100
        per_type_out[t] = {'dr': round(dr, 1),
                           'dr_ci': [round(ci[0]*100, 1), round(ci[1]*100, 1)],
                           'dr_fixed_theta': round(dr_p, 1),
                           'n_windows': v['n'], 'tp': v['tp']}
        print(f"    {t:18s}: {dr:5.1f}% / {dr_p:5.1f}%  (n_windows={v['n']:>7d})")

    out = {
        'metadata': {
            'dataset': 'LITNET-2020',
            'semantic': f'L1 protected-subnet aggregation (/{prefix_bits}, true-union HLL)',
            'mechanism_under_test': 'ip_protected_subnet_add + Stage-3c keying',
            'distinct_from': 'experiment/run_litnet_zone.py (which uses the L2-zone post-hoc sum)',
            'feature_count': len(LITNET_FEATURES),
            'features_used': list(LITNET_FEATURES),
            'features': list(LITNET_FEATURES),
            'features_inert_auto_excluded': globals().get(f'_INERT_FEATURES_{prefix_bits}', []),
            'production_feature_set_size': len(PRODUCTION_39_FEATURES),
            'min_windows_per_subnet': MIN_WINDOWS_PER_SUBNET,
            'min_attack_windows_for_victim': MIN_ATTACK_WINDOWS_FOR_DR,
            'n_subnets_total': len(results),
            'n_victim_subnets': len(victims),
            'n_uninvolved_subnets': len(uninvolved),
        },
        'split_metrics': {
            'dr_on_victims_pct': round(v_dr, 1),
            'dr_on_victims_ci': [round(v_ci[0]*100, 1), round(v_ci[1]*100, 1)],
            'fpr_on_uninvolved_pct': u_fpr_out,
            'fpr_on_uninvolved_ci': u_ci_out,
            'fpr_on_uninvolved_cluster_ci': u_cluster_out,
            'fpr_unmeasurable_reason': None if has_uninvolved else 'no uninvolved subnets (all in-scope subnets contain attack windows)',
            'dr_on_victims_fixed_theta_pct': round(v_dr_p, 1),
            'fpr_on_uninvolved_fixed_theta_pct': u_fpr_p_out,
            'tp_on_victims': v_tp, 'fn_on_victims': v_fn,
            'fp_on_uninvolved': u_fp, 'tn_on_uninvolved': u_tn,
        },
        'per_attack_type': per_type_out,
        'top_victim_subnets': [
            {'subnet': r['subnet'], 'n_attack': r['n_attack'], 'n_benign': r['n_benign'],
             'dr': round(r['tp'] / max(r['n_attack'], 1) * 100, 1),
             'fpr': round(r['fp'] / max(r['n_benign'], 1) * 100, 1),
             'theta': r['theta'],
             'dominant_attack': (max(r['per_type'].items(), key=lambda x: x[1]['n'])[0]
                                 if r['per_type'] else None)}
            for r in sorted(victims, key=lambda x: -x['n_attack'])[:10]
        ],
    }

    out_path = output_path_for(prefix_bits)
    os.makedirs(RESULTS_DIR, exist_ok=True)
    with open(out_path, 'w') as f:
        json.dump(out, f, indent=2)
    print(f"  Saved: {out_path}")
    return out


def main():
    t0 = time.time()
    print("=== LITNET-2020 L1-semantic subnet evaluation ===")
    print("(true-union HLL over subnet sources, matching ip_protected_subnet_add)")

    results = {}
    for prefix_bits in (24, 16):
        results[f'/{prefix_bits}'] = run_for_prefix(prefix_bits)

    print(f"\nTotal runtime: {time.time() - t0:.1f}s")
    print("\n=== Comparison summary (L1 vs L2-zone) ===")
    print(f"  Aggregate DR on victim subnets:")
    for tag, r in results.items():
        if r is None: continue
        sm = r['split_metrics']
        print(f"    {tag}: L1 DR {sm['dr_on_victims_pct']}% calib / {sm['dr_on_victims_fixed_theta_pct']}% fixed-θ")
    print("  Compare against `experiment/results/litnet_zone_results.json` for L2-zone numbers.")


if __name__ == '__main__':
    main()
