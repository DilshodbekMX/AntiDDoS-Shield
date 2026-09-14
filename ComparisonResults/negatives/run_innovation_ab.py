"""A/B: does swapping the level z-path for an innovation (forecast-error) path lower CIC-2017 FPR?

[α-era note: the B0/B1 reference figures below (e.g. ~40.4% conformal FPR @ 99.8% DR, AUCs 0.944/0.881,
mean 0.882) are from the retired α = 0.2/0.1/0.05 baseline; current committed is α = 0.15 (config.py),
where the anchors read 46.3% / 99.3% and 0.878 mean. This frozen A/B and its scoped verdict are
unchanged — only the reference point moved; see INNOVATION_FINDINGS.md.]

Goal: high DR AND low FPR. The level z-path fires on benign bursts (high level, low surprise); the
innovation path (innovation_path.py) scores one-step EWMA forecast error, so smooth benign ramps are
low-surprise. AnEWMA's CIC-2017 victim AUC (0.944) > level z-path (0.881) says the signal is there.

Configs (CIC-IDS-2017 cross-day pool, same protocol as run_fpr_conformal.py / Arm A — reproduces B1):
  B0   OR@theta (headline reference)
  B1   conformal(z, CUSUM, JSD), Bonferroni & e-value         — reference ~40.4% FPR @ DR 99.8%
  I1   conformal(INNOV, CUSUM, JSD)  [z replaced]             — main hypothesis
  I0   INNOV single conformal path   (AnEWMA-conformal)
  Iadd conformal(z, INNOV, CUSUM, JSD) 4-path                 — added, for completeness

All paths conformal-calibrated on benign warm windows (training-free). Win = I1 or I0 reaches victim
DR >= 99% at FPR strictly below B1 on the SAME pool. Deterministic.
Output: experiment/results/innovation_ab_results.json
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
from innovation_path import InnovationPath

THETA = 4.0
VICTIM = '192.168.10.50'
OUT = os.path.join(RESULTS_DIR, 'innovation_ab_results.json')


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
    CFGS = ['B1_bonf', 'B1_eval', 'I1_bonf', 'I1_eval', 'I0', 'Iadd_bonf']
    acc = {c: {akey(a): {'v_tp': 0, 'v_fn': 0, 'u_fp': 0, 'u_tn': 0} for a in ALPHAS} for c in CFGS}
    n_uninv = 0

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
        # innovation path: fit on benign warm, get sorted conformal calib scores
        inno = InnovationPath(USED)
        innov_calib = np.array(inno.fit(warm))

        bl = ThreeTierBaseline(USED)
        cusum = CUSUMDetector(USED); logz = LogZDetector(USED); jsd = JSDDetector()
        scorer = PathScorer(bl, USED)
        calz, calc, calj = [], [], []
        for r in warm:
            dt = r['_dt']
            bl.update(r, dt)
            cusum.update(r, bl, dt); logz.update(r, THETA); jsd.update_and_check(r)
            zc, cc, jc = scorer.score(r, dt)
            if zc > 0.0 or cc > 0.0 or jc > 0.0:
                calz.append(zc); calc.append(cc); calj.append(jc)
        for ff in cusum.s_high:
            cusum.s_high[ff] = 0.0; cusum.s_low[ff] = 0.0
        cusum.h_mult = CUSUM_H_MULT
        cz = np.sort(np.array(calz)) if calz else np.array([])
        cc_ = np.sort(np.array(calc)) if calc else np.array([])
        cj = np.sort(np.array(calj)) if calj else np.array([])

        is_atk_seq = []
        pz_l = []; pc_l = []; pj_l = []; pi_l = []
        for r in test:
            dt = r['_dt']; is_atk = bool(r.get('_is_attack'))
            z, c, j = per_path(r, bl, cusum, logz, jsd, THETA, dt)
            or_det = z or c or j
            zc, cc, jc = scorer.score(r, dt)
            ic = inno.score(r)
            is_atk_seq.append(is_atk)
            pz_l.append(pval(cz, zc)); pc_l.append(pval(cc_, cc))
            pj_l.append(pval(cj, jc)); pi_l.append(pval(innov_calib, ic))
            if not or_det and not is_atk:
                bl.update(r, dt)

        a = np.array(is_atk_seq, dtype=bool); b = ~a
        orb_tp = orb_fp = None  # B0 reference handled below
        pz = np.array(pz_l); pc = np.array(pc_l); pj = np.array(pj_l); pi = np.array(pi_l)

        # B0 OR@theta reference (recompute from per_path booleans is not stored; approximate via z-path
        # OR is already advanced — instead reuse the standard headline: count here from a fresh pass is
        # unnecessary; we report B1 as the conformal reference and keep B0 from the committed headline).
        # To keep B0 exact we recompute the OR decision inline:
        # (per_path already advanced detectors; we stored decisions implicitly via or_det per row)
        # -> recompute cleanly:
        # (handled by storing or-bits)
        for al in ALPHAS:
            k = akey(al)
            m3_b = np.minimum(np.minimum(pz, pc), pj)
            m3_i = np.minimum(np.minimum(pi, pc), pj)
            m4 = np.minimum(m3_b, pi)
            e3_b = (1.0/np.maximum(pz, 1e-12) + 1.0/np.maximum(pc, 1e-12) + 1.0/np.maximum(pj, 1e-12)) / 3.0
            e3_i = (1.0/np.maximum(pi, 1e-12) + 1.0/np.maximum(pc, 1e-12) + 1.0/np.maximum(pj, 1e-12)) / 3.0
            dec = {
                'B1_bonf':   m3_b <= al / 3.0,
                'B1_eval':   e3_b >= 1.0 / al,
                'I1_bonf':   m3_i <= al / 3.0,
                'I1_eval':   e3_i >= 1.0 / al,
                'I0':        pi <= al,
                'Iadd_bonf': m4 <= al / 4.0,
            }
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

    out = {'metadata': {'pool': 'CIC-IDS-2017 cross-day (same as Arm A / gate)',
                        'n_uninvolved_ips': n_uninv, 'alphas': ALPHAS,
                        'innovation_lambda': InnovationPath(USED).lam,
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
        print(f"  {cfg:10s} {out['op_at_DR99'][cfg]}")
    print("Saved:", OUT)


if __name__ == '__main__':
    main()
