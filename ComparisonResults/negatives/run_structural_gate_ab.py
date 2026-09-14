"""Integration A/B: does a structural conjunctive VETO lower CIC-IDS-2017 FPR below B1 (40.4%)?

[α-era note: the B1 reference 40.4% (conformal Bonferroni FPR) is from the retired α = 0.2/0.1/0.05
baseline; current committed is α = 0.15 (config.py), where it reads 46.3%. This frozen A/B and its
negative verdict are unchanged — only the reference point moved; see STRUCTURAL_FINDINGS.md.]

From the single-feature pilot (run_structural_pilot.py), five inbound-only structural features clear
AUC>=0.70 (attack vs benign-burst) on CIC-IDS-2017: ack_to_syn, nonsyn_to_syn, bytes_per_packet,
small_pkt_ratio, syn_share. A structural OR-path would only raise FPR; the FPR lever is a CONJUNCTIVE
gate — alarm only if the volume/conformal path fires AND the structure looks tool-generated.

Configs (same cross-day pool/protocol as run_fpr_conformal.py / run_mahalanobis_ab.py Arm A):
  B0   OR@theta (headline reference)
  B1   3-path conformal, Bonferroni  min(pz,pc,pj) <= a/3
  Gall B1 AND (min structural conformal p <= a)        — any tool-fingerprint present
  Gsmp B1 AND (small_pkt_ratio conformal p <= a)        — single best general structural feature

Structural p-values are one-sided split-conformal (committed direction), calibrated on benign warm
windows only — training-free. A gate can only LOWER DR vs B1, so the test is whether FPR falls more
than DR at a matched DR>=99% operating point. Deterministic.
Output: experiment/results/structural_gate_ab_results.json
"""
import os, sys, json, time
import numpy as np
sys.path.insert(0, os.path.dirname(__file__))
from config import CUSUM_H_MULT, RESULTS_DIR
from baselines import ThreeTierBaseline
from detectors import CUSUMDetector, LogZDetector, JSDDetector
from feature_filter import filter_active, PRODUCTION_39_FEATURES
from run_cicids2017_pcap import (MONDAY_FEATURES_JSON, FRIDAY_FEATURES_JSON,
                                 MIN_ROWS_PER_IP, MIN_ATTACK_WINDOWS_FOR_DR, epoch_to_dt)
from run_fpr_mitigation import per_path
from run_fpr_conformal import PathScorer, pval, ALPHAS, akey

THETA = 4.0
VICTIM = '192.168.10.50'
EPS = 1e-6
CAP = 1e6
OUT = os.path.join(RESULTS_DIR, 'structural_gate_ab_results.json')


def F(r, k):
    return float(r.get(k, 0.0) or 0.0)


# (name, direction); oriented score = val if 'high' else -val  (right tail = anomalous)
STRUCT = [
    ('ack_to_syn',       'low',  lambda r: min(F(r, 'ack_per_sec') / (F(r, 'syn_per_sec') + EPS), CAP)),
    ('nonsyn_to_syn',    'low',  lambda r: min(max(F(r, 'packets_per_sec') - F(r, 'syn_per_sec'), 0.0) / (F(r, 'syn_per_sec') + EPS), CAP)),
    ('bytes_per_packet', 'low',  lambda r: F(r, 'bytes_per_packet')),
    ('small_pkt_ratio',  'high', lambda r: F(r, 'small_pkt_ratio')),
    ('syn_share',        'high', lambda r: F(r, 'syn_per_sec') / (F(r, 'packets_per_sec') + EPS)),
]


def oriented(name_dir_fn, r):
    _, d, fn = name_dir_fn
    v = fn(r)
    return v if d == 'high' else -v


def rate(num, den):
    return round(100.0 * num / den, 1) if den else None


def main():
    t0 = time.time()
    mon = json.load(open(MONDAY_FEATURES_JSON))['per_ip_windows']
    fri = json.load(open(FRIDAY_FEATURES_JSON))['per_ip_windows']
    sample = []
    for rows in mon.values():
        sample.extend(rows[:50])
        if len(sample) >= 5000:
            break
    USED, _ = filter_active(PRODUCTION_39_FEATURES, sample)

    atk_t = sorted(r['_dt'] for rows in fri.values() for r in rows if r.get('_is_attack'))
    t_start = atk_t[0]
    t_start_dt = epoch_to_dt(t_start) if isinstance(t_start, (int, float)) else t_start
    common = set(mon) & set(fri)
    eligible = sorted(ip for ip in common
                      if len(mon[ip]) >= MIN_ROWS_PER_IP and len(fri[ip]) >= MIN_ROWS_PER_IP)

    ref = {'tp': 0, 'fn': 0, 'fp': 0, 'tn': 0}
    CFGS = ['B1', 'Gall', 'Gsmp']
    acc = {c: {akey(a): {'v_tp': 0, 'v_fn': 0, 'u_fp': 0, 'u_tn': 0} for a in ALPHAS} for c in CFGS}
    n_uninv = 0
    smp_idx = [i for i, s in enumerate(STRUCT) if s[0] == 'small_pkt_ratio'][0]

    for n_done, ip in enumerate(eligible):
        m_rows = list(mon[ip]); f_rows = list(fri[ip])
        for r in m_rows + f_rows:
            if isinstance(r.get('_dt'), (int, float)):
                r['_dt'] = epoch_to_dt(r['_dt'])
        m_rows.sort(key=lambda r: r.get('_id_time', 0)); f_rows.sort(key=lambda r: r.get('_id_time', 0))
        bridge = [r for r in f_rows if r['_dt'] < t_start_dt and not r.get('_is_attack')]
        test = [r for r in f_rows if r['_dt'] >= t_start_dt]
        if len(test) < 5:
            continue
        n_atk = sum(1 for r in test if r.get('_is_attack'))
        n_ben = sum(1 for r in test if not r.get('_is_attack'))
        is_victim = (ip == VICTIM and n_atk >= MIN_ATTACK_WINDOWS_FOR_DR)
        is_uninv = (n_atk == 0 and n_ben >= 30)
        if not (is_victim or is_uninv):
            continue

        warm = m_rows + bridge
        bl = ThreeTierBaseline(USED)
        cusum = CUSUMDetector(USED); logz = LogZDetector(USED); jsd = JSDDetector()
        scorer = PathScorer(bl, USED)
        calz, calc, calj = [], [], []
        cal_struct = [[] for _ in STRUCT]
        for r in warm:
            dt = r['_dt']
            bl.update(r, dt)
            cusum.update(r, bl, dt); logz.update(r, THETA); jsd.update_and_check(r)
            zc, cc, jc = scorer.score(r, dt)
            if zc > 0.0 or cc > 0.0 or jc > 0.0:
                calz.append(zc); calc.append(cc); calj.append(jc)
            for i, s in enumerate(STRUCT):
                cal_struct[i].append(oriented(s, r))
        for ff in cusum.s_high:
            cusum.s_high[ff] = 0.0; cusum.s_low[ff] = 0.0
        cusum.h_mult = CUSUM_H_MULT
        cz = np.sort(np.array(calz)) if calz else np.array([])
        cc_ = np.sort(np.array(calc)) if calc else np.array([])
        cj = np.sort(np.array(calj)) if calj else np.array([])
        cs = [np.sort(np.array(c)) for c in cal_struct]

        is_atk_seq = []
        pz_l = []; pc_l = []; pj_l = []
        ps_l = [[] for _ in STRUCT]
        for r in test:
            dt = r['_dt']; is_atk = bool(r.get('_is_attack'))
            z, c, j = per_path(r, bl, cusum, logz, jsd, THETA, dt)
            or_det = z or c or j
            zc, cc, jc = scorer.score(r, dt)
            is_atk_seq.append(is_atk)
            pz_l.append(pval(cz, zc)); pc_l.append(pval(cc_, cc)); pj_l.append(pval(cj, jc))
            for i, s in enumerate(STRUCT):
                ps_l[i].append(pval(cs[i], oriented(s, r)))
            if not or_det and not is_atk:
                bl.update(r, dt)

        a = np.array(is_atk_seq, dtype=bool); b = ~a
        pz = np.array(pz_l); pc = np.array(pc_l); pj = np.array(pj_l)
        ps = [np.array(x) for x in ps_l]
        struct_min = np.minimum.reduce(ps)
        p_smp = ps[smp_idx]
        m3 = np.minimum(np.minimum(pz, pc), pj)

        if is_victim:
            # B0 reference DR uses OR@theta — recompute or_bits cheaply via per-path already advanced;
            # for the reference we reuse min3 conformal? No: B0 = OR@theta. Track separately.
            pass
        for al in ALPHAS:
            k = akey(al)
            b1 = m3 <= al / 3.0
            dec = {'B1': b1, 'Gall': b1 & (struct_min <= al), 'Gsmp': b1 & (p_smp <= al)}
            for cfg, d in dec.items():
                g = acc[cfg][k]
                if is_victim:
                    g['v_tp'] += int((d & a).sum()); g['v_fn'] += int((~d & a).sum())
                else:
                    g['u_fp'] += int((d & b).sum()); g['u_tn'] += int((~d & b).sum())
        if not is_victim:
            n_uninv += 1
        if (n_done + 1) % 150 == 0:
            print(f"  [{n_done+1}/{len(eligible)}] uninv={n_uninv} {time.time()-t0:.0f}s")

    out = {'metadata': {'pool': 'CIC-IDS-2017 cross-day (same as Arm A)', 'n_uninvolved_ips': n_uninv,
                        'structural_features': [s[0] for s in STRUCT], 'alphas': ALPHAS,
                        'runtime_s': round(time.time()-t0, 1)},
           'grid': {}}
    for cfg in CFGS:
        out['grid'][cfg] = {k: {'victim_DR_pct': rate(g['v_tp'], g['v_tp']+g['v_fn']),
                                'uninvolved_FPR_pct': rate(g['u_fp'], g['u_fp']+g['u_tn'])}
                            for k, g in acc[cfg].items()}

    def best_op(cfg):
        best = None
        for k, v in out['grid'][cfg].items():
            dr, fpr = v['victim_DR_pct'], v['uninvolved_FPR_pct']
            if dr is not None and fpr is not None and dr >= 99.0:
                if best is None or fpr < best['FPR_pct']:
                    best = {'alpha_key': k, 'DR_pct': dr, 'FPR_pct': fpr}
        return best
    out['op_at_DR99'] = {cfg: best_op(cfg) for cfg in CFGS}
    json.dump(out, open(OUT, 'w'), indent=2)
    print("\n=== op @ victim DR>=99% (CIC-IDS-2017) ===")
    for cfg in CFGS:
        print(f"  {cfg:5s} {out['op_at_DR99'][cfg]}")
    print("Saved:", OUT)


if __name__ == '__main__':
    main()
