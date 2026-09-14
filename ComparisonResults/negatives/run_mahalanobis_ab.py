"""A/B test: does a training-free covariance-aware (Mahalanobis) path beat the current detector?

Spec: experiment/MAHALANOBIS_PROTOTYPE_BRIEF.md. Harness prototype only (no C, no paper).

Configs (identical splits & active features, all training-free — attack labels only score metrics):
  B0  current OR ensemble  (z v CUSUM v JSD, theta=4.0)         — reproduces the headline
  B1  current conformal combination (z,CUSUM,JSD; Bonferroni & e-value)
  M1  Mahalanobis-conformal, single path                        — main hypothesis
  M2  Mahalanobis added to {z,CUSUM,JSD} under family-wise control (4 paths)

Arms (selectable via env MAHA_ARMS, default 'A,B,C'):
  A  CIC-IDS-2017 cross-day pool (530 uninvolved + victim 192.168.10.50): per-window FPR / DR.
     Same pool/protocol as run_fpr_conformal.py so B0->75.4/99.6 and B1(bonf,bp10)->~40.4 reproduce
     (α=0.2-era anchors; this A/B is frozen at that baseline — current committed is 71.8/99.3, see MAHALANOBIS_FINDINGS.md).
  B  Threshold-free ROC-AUC on the documented victim cases (reuses run_anewma_allsets case list):
     LITNET HTTP flood, CIC-IoT SYN_Flood, and the full 13-case mean (regression check vs 0.882).
  C  CESNET benign FPR regression (must stay near 3.49%, not blow up).

Win = M1 or M2 STRICTLY improves BOTH (a) CIC-2017 FPR vs B1 AND (b) >=1 worst-case AUC vs B0,
with no material regression on CESNET FPR or the 13-case mean. Otherwise: honest negative, STOP.

Mahalanobis fit/calibration is disjoint (conformal validity): mu/Sigma fit on the first 85% of the
benign warm rows, the conformal calibration d2 set is the held-out last 15%. Deterministic (no RNG).
Output: experiment/results/mahalanobis_ab_results.json
"""
import os, sys, json, time, gc
import numpy as np
sys.path.insert(0, os.path.dirname(__file__))
from config import CUSUM_H_MULT, RESULTS_DIR, TAR_PATH, TIMES_TAR, MIN_IP_ROWS_PER_IP, CALIB_TARGET_FPR
from baselines import ThreeTierBaseline
from detectors import CUSUMDetector, LogZDetector, JSDDetector
from feature_filter import filter_active, PRODUCTION_39_FEATURES
from run_cicids2017_pcap import (MONDAY_FEATURES_JSON, FRIDAY_FEATURES_JSON,
                                 MIN_ROWS_PER_IP, MIN_ATTACK_WINDOWS_FOR_DR, epoch_to_dt)
from run_fpr_mitigation import per_path
from run_fpr_conformal import PathScorer, pval, ALPHAS, akey
from mahalanobis import MahalanobisPath, maha_scores
from sklearn.metrics import roc_auc_score

THETA = 4.0
VICTIM = '192.168.10.50'
M_FIT_FRAC = 0.85          # fit mu/Sigma on first 85% of warm benign; calibrate d2 on last 15%
OUT = os.path.join(RESULTS_DIR, 'mahalanobis_ab_results.json')
ARMS = os.environ.get('MAHA_ARMS', 'A,B,C').split(',')


def rate(num, den):
    return round(100.0 * num / den, 1) if den else None


# ============================== ARM A: CIC-IDS-2017 FPR/DR ==============================
def arm_a():
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

    # accumulators
    ref = {'tp': 0, 'fn': 0, 'fp': 0, 'tn': 0}                       # B0 OR@theta
    CFGS = ['M1', 'B1_bonf', 'B1_eval', 'M2_bonf', 'M2_eval']
    acc = {c: {akey(a): {'v_tp': 0, 'v_fn': 0, 'u_fp': 0, 'u_tn': 0} for a in ALPHAS} for c in CFGS}
    n_uninv = 0; n_skip_m = 0

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
        # --- Mahalanobis fit (first 85% of warm benign) + disjoint conformal calib (last 15%) ---
        cut = int(len(warm) * M_FIT_FRAC)
        mp = MahalanobisPath().fit(warm[:cut], USED)
        if not mp.ok or len(warm) - cut < 20:
            n_skip_m += 1
            continue                              # keep pools identical across all configs
        m_calib = np.sort(mp.score_many(warm[cut:]))

        # --- z/CUSUM/JSD streaming warm pass (collect conformal calib over full warm, cross-day) ---
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

        # --- test pass ---
        or_bits = []; is_atk_seq = []
        pz_l = []; pc_l = []; pj_l = []; pm_l = []
        for r in test:
            dt = r['_dt']; is_atk = bool(r.get('_is_attack'))
            z, c, j = per_path(r, bl, cusum, logz, jsd, THETA, dt)
            or_det = z or c or j
            zc, cc, jc = scorer.score(r, dt)
            d2 = mp.score(r)
            or_bits.append(or_det); is_atk_seq.append(is_atk)
            pz_l.append(pval(cz, zc)); pc_l.append(pval(cc_, cc))
            pj_l.append(pval(cj, jc)); pm_l.append(pval(m_calib, d2))
            if not or_det and not is_atk:
                bl.update(r, dt)

        a = np.array(is_atk_seq, dtype=bool); b = ~a
        orb = np.array(or_bits, dtype=bool)
        pz = np.array(pz_l); pc = np.array(pc_l); pj = np.array(pj_l); pm = np.array(pm_l)

        if is_victim:
            ref['tp'] += int((orb & a).sum()); ref['fn'] += int((~orb & a).sum())
        else:
            n_uninv += 1
            ref['fp'] += int((orb & b).sum()); ref['tn'] += int((~orb & b).sum())

        for al in ALPHAS:
            k = akey(al)
            m_min3 = np.minimum(np.minimum(pz, pc), pj)
            m_min4 = np.minimum(m_min3, pm)
            e3 = (1.0/np.maximum(pz, 1e-12) + 1.0/np.maximum(pc, 1e-12) + 1.0/np.maximum(pj, 1e-12)) / 3.0
            e4 = (e3 * 3.0 + 1.0/np.maximum(pm, 1e-12)) / 4.0
            dec = {
                'M1':      pm <= al,
                'B1_bonf': m_min3 <= al / 3.0,
                'B1_eval': e3 >= 1.0 / al,
                'M2_bonf': m_min4 <= al / 4.0,
                'M2_eval': e4 >= 1.0 / al,
            }
            for cfg, d in dec.items():
                g = acc[cfg][k]
                if is_victim:
                    g['v_tp'] += int((d & a).sum()); g['v_fn'] += int((~d & a).sum())
                else:
                    g['u_fp'] += int((d & b).sum()); g['u_tn'] += int((~d & b).sum())

        if (n_done + 1) % 100 == 0:
            print(f"    [A {n_done+1}/{len(eligible)}] uninv={n_uninv} skipM={n_skip_m} "
                  f"{time.time()-t0:.0f}s")

    out = {
        'B0_OR_theta': {'victim_DR_pct': rate(ref['tp'], ref['tp']+ref['fn']),
                        'uninvolved_FPR_pct': rate(ref['fp'], ref['fp']+ref['tn']),
                        'note': 'reproduces the α=0.2-era headline ~99.6% / ~75.4% (frozen; current committed 99.3% / 71.8%)'},
        'grid': {}, 'n_uninvolved_ips': n_uninv, 'n_skipped_maha': n_skip_m,
        'used_features': len(USED), 'runtime_s': round(time.time()-t0, 1),
    }
    for cfg in CFGS:
        out['grid'][cfg] = {k: {'victim_DR_pct': rate(g['v_tp'], g['v_tp']+g['v_fn']),
                                'uninvolved_FPR_pct': rate(g['u_fp'], g['u_fp']+g['u_tn'])}
                            for k, g in acc[cfg].items()}
    # operating-point summary: lowest FPR with victim DR >= 99.0, per config
    def best_op(cfg):
        best = None
        for k, v in out['grid'][cfg].items():
            dr, fpr = v['victim_DR_pct'], v['uninvolved_FPR_pct']
            if dr is not None and fpr is not None and dr >= 99.0:
                if best is None or fpr < best['FPR_pct']:
                    best = {'alpha_key': k, 'DR_pct': dr, 'FPR_pct': fpr}
        return best
    out['op_at_DR99'] = {cfg: best_op(cfg) for cfg in CFGS}
    print(f"  ARM A done: B0={out['B0_OR_theta']}  ({n_uninv} uninv, {n_skip_m} skipM)")
    return out


# ============================== ARM B: ROC-AUC cases ==============================
def arm_b():
    import run_crosscorpus_auc as R
    t0 = time.time()
    cases = []   # (label, train, test)

    def add(label, train, test):
        benign = [r for r in test if not r.get('_is_attack')]
        attack = [r for r in test if r.get('_is_attack')]
        if len(attack) < 5 or len(benign) < 5 or len(train) < 30:
            print(f"    {label}: skipped (degenerate)"); return
        feats = R.active_features(train)
        if not feats:
            print(f"    {label}: skipped (no feats)"); return
        eval_rows = benign + attack
        y = np.array([False]*len(benign) + [True]*len(attack))
        s_ours = R.our_zscores(train, eval_rows, feats)
        s_maha = maha_scores(train, eval_rows, feats)
        cases.append({'label': label, 'n_train': len(train), 'n_attack': int(y.sum()),
                      'n_benign_test': int((~y).sum()), 'n_features': len(feats),
                      'ours_auc': round(roc_auc_score(y, s_ours), 3),
                      'maha_auc': round(roc_auc_score(y, s_maha), 3),
                      'ours_dr_at_fpr5': R.dr_at_fpr(s_ours, y),
                      'maha_dr_at_fpr5': R.dr_at_fpr(s_maha, y)})
        c = cases[-1]
        print(f"    {label:44s} feats={c['n_features']:2d} atk={c['n_attack']:6d} "
              f"ours={c['ours_auc']:.3f}  maha={c['maha_auc']:.3f}")

    # 1) CIC-IDS-2017 Friday cross-day victim
    try:
        mon = R.load_perip('cicids2017_pcap_monday.json'); fri = R.load_perip('cicids2017_pcap_friday.json')
        v = '192.168.10.50'
        if v in mon and v in fri:
            train = [r for r in mon[v] if not r.get('_is_attack')]
            test = sorted(fri[v], key=lambda r: r.get('_id_time', r.get('_dt', 0)))
            add('CIC-IDS-2017 Friday (cross-day victim)', train, test)
        del mon, fri; gc.collect()
    except Exception as ex:
        print("    CIC-IDS-2017 Friday skipped:", ex)
    # 2) CIC-IDS-2018 Wed/Thu/Fri
    for cache, v, tag in [('cicids2018_pcap_wed.json', '172.31.69.28', 'Wed LOIC-UDP+HOIC'),
                          ('cicids2018_pcap_thu.json', '172.31.69.25', 'Thu GoldenEye+Slowloris'),
                          ('cicids2018_pcap_fri.json', '172.31.69.25', 'Fri Hulk+SlowHTTPTest')]:
        try:
            d = R.load_perip(cache)
            if v in d:
                tr, te = R.split_within_cache(d[v]); add(f'CIC-IDS-2018 {tag}', tr, te)
            del d; gc.collect()
        except Exception as ex:
            print(f"    CIC-IDS-2018 {tag} skipped:", ex)
    # 3) CIC-DDoS2019
    try:
        d = R.load_perip('cicddos_pcap_features.json'); v = '192.168.50.4'
        if v in d:
            tr, te = R.split_within_cache(d[v]); add('CIC-DDoS2019 (victim flood)', tr, te)
        del d; gc.collect()
    except Exception as ex:
        print("    CIC-DDoS2019 skipped:", ex)
    # 4) LITNET concentrated victims
    try:
        lit = json.load(open(os.path.join(R.CACHE_DIR, 'litnet_per_ip_cache.json')))
        for v, tag in [('193.219.81.138', 'Code Red worm'), ('193.219.88.36', 'Smurf'),
                       ('23.32.104.60', 'HTTP flood')]:
            if v in lit:
                tr, te = R.split_within_cache(lit[v]); add(f'LITNET {tag} (victim)', tr, te)
        del lit; gc.collect()
    except Exception as ex:
        print("    LITNET skipped:", ex)
    # 5) CIC-IoT-2023 per-family victim-internal
    try:
        ben = R.load_perip('cicios2023_benign.json')
        for fam in ['DDoS-SlowLoris', 'DDoS-SYN_Flood', 'DDoS-ICMP_Fragmentation',
                    'DDoS-HTTP_Flood', 'Mirai-udpplain']:
            fpath = f'cicios2023_{fam}.json'
            if not os.path.exists(os.path.join(R.CACHE_DIR, fpath)):
                continue
            fam_d = R.load_perip(fpath)
            best = None
            for ip, rs in fam_d.items():
                if not ip.startswith('192.168.137.') or ip.endswith('.1') or ip.endswith('.255'):
                    continue
                atk_rows = [x for x in rs if x.get('_is_attack')]; na = len(atk_rows)
                if na < 30 or len(ben.get(ip, [])) < 60:
                    continue
                max_pps = max((float(x.get('packets_per_sec', 0.0) or 0.0) for x in atk_rows), default=0.0)
                if max_pps < 100:
                    continue
                if best is None or na > best[1]:
                    best = (ip, na)
            if best is None:
                del fam_d; continue
            ip = best[0]
            brows = sorted([r for r in ben[ip] if not r.get('_is_attack')],
                           key=lambda r: r.get('_id_time', r.get('_dt', 0)))
            arows = [r for r in fam_d[ip] if r.get('_is_attack')]
            n = len(brows); ntr = int(n*0.6); nbr = int(n*0.2)
            train = brows[:ntr+nbr]
            test = sorted(brows[ntr+nbr:] + arows, key=lambda r: r.get('_id_time', r.get('_dt', 0)))
            add(f'CIC-IoT-2023 {fam} (victim {ip})', train, test)
            del fam_d; gc.collect()
        del ben; gc.collect()
    except Exception as ex:
        print("    CIC-IoT-2023 skipped:", ex)

    def pick(substr):
        for c in cases:
            if substr in c['label']:
                return c
        return None
    summary = {
        'n_cases': len(cases),
        'mean_auc_ours': round(float(np.mean([c['ours_auc'] for c in cases])), 3) if cases else None,
        'mean_auc_maha': round(float(np.mean([c['maha_auc'] for c in cases])), 3) if cases else None,
        'maha_wins': sum(1 for c in cases if c['maha_auc'] > c['ours_auc']),
        'ours_wins': sum(1 for c in cases if c['ours_auc'] > c['maha_auc']),
        'litnet_http': pick('HTTP flood'),
        'cic_iot_syn': pick('SYN_Flood'),
        'runtime_s': round(time.time()-t0, 1),
    }
    print(f"  ARM B done: {summary['n_cases']} cases; mean AUC ours={summary['mean_auc_ours']} "
          f"maha={summary['mean_auc_maha']}; maha_wins={summary['maha_wins']}")
    return {'summary': summary, 'cases': cases}


# ============================== ARM C: CESNET FPR regression ==============================
def arm_c():
    from data_loader import load_per_ip
    t0 = time.time()
    alpha = CALIB_TARGET_FPR                      # 0.03 — matches the production target behind 3.49%
    ip_rows = load_per_ip(TAR_PATH, TIMES_TAR, min_rows=MIN_IP_ROWS_PER_IP)
    sample = []
    for rows in ip_rows.values():
        sample.extend(rows[:50])
        if len(sample) >= 5000:
            break
    USED, _ = filter_active(PRODUCTION_39_FEATURES, sample)

    fp = tn = 0; n_ip = 0; n_skip = 0
    for ip, rows in ip_rows.items():
        ben = sorted([r for r in rows if not r.get('_is_attack')],
                     key=lambda r: r.get('_id_time', r.get('_dt', 0)))
        n = len(ben)
        if n < 100:
            n_skip += 1; continue
        ntr = int(n*0.60); ncal = int(n*0.15)
        train, calib, test = ben[:ntr], ben[ntr:ntr+ncal], ben[ntr+ncal:]
        if len(calib) < 20 or len(test) < 10:
            n_skip += 1; continue
        mp = MahalanobisPath().fit(train, USED)
        if not mp.ok:
            n_skip += 1; continue
        cal_sorted = np.sort(mp.score_many(calib))
        d2_test = mp.score_many(test)
        pvals = np.array([pval(cal_sorted, s) for s in d2_test])
        fp += int((pvals <= alpha).sum()); tn += int((pvals > alpha).sum())
        n_ip += 1
    cesnet_fpr = rate(fp, fp + tn)
    print(f"  ARM C done: CESNET M1 FPR={cesnet_fpr}% (alpha={alpha}) over {n_ip} IPs "
          f"({n_skip} skipped), {time.time()-t0:.0f}s")
    return {'M1_FPR_pct': cesnet_fpr, 'alpha': alpha, 'n_ips': n_ip, 'n_skipped': n_skip,
            'reference_ours_FPR_pct': 3.49, 'used_features': len(USED),
            'runtime_s': round(time.time()-t0, 1)}


def main():
    t0 = time.time()
    result = {'metadata': {
        'seed': 'n/a (deterministic; LedoitWolf + numpy, no RNG)',
        'splits': {'cic2017': 'cross-day (Monday+bridge warm, Friday-attack test); '
                              'Mahalanobis fit 85% warm / calib 15% warm',
                   'auc_cases': 'benign 60/20 train / held-out 20% benign + attack test',
                   'cesnet': 'benign 60/15/25 train/calib/test'},
        'alphas': ALPHAS, 'theta': THETA, 'm_fit_frac': M_FIT_FRAC,
        'log_transform': 'baselines._log_xform (3 cardinality features; matches z-path, see mahalanobis.py)',
        'arms_run': ARMS}}
    if 'A' in ARMS:
        print("[ARM A] CIC-IDS-2017 cross-day FPR/DR ...")
        result['arm_a_cic2017'] = arm_a(); gc.collect()
    if 'B' in ARMS:
        print("[ARM B] ROC-AUC victim cases ...")
        result['arm_b_auc'] = arm_b(); gc.collect()
    if 'C' in ARMS:
        print("[ARM C] CESNET FPR regression ...")
        result['arm_c_cesnet'] = arm_c(); gc.collect()
    result['metadata']['total_runtime_s'] = round(time.time()-t0, 1)

    # merge with any prior partial result so arm-by-arm runs accumulate into one JSON
    if os.path.exists(OUT):
        try:
            prev = json.load(open(OUT))
            for k in ('arm_a_cic2017', 'arm_b_auc', 'arm_c_cesnet'):
                if k not in result and k in prev:
                    result[k] = prev[k]
        except Exception:
            pass
    json.dump(result, open(OUT, 'w'), indent=2)
    print("Saved:", OUT)


if __name__ == '__main__':
    main()
