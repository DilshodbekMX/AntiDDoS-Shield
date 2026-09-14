"""A/B: moving-reference (NEWMA) path vs the shipped CUSUM path, inside the OR ensemble.

HARNESS-ONLY PROTOTYPE (l2-detector-prototyping, training-free A/B). Nothing here
touches committed source, layer2/*.c, or the paper. Target = CIC-IDS-2017 per-IP
cross-day (Monday train -> Friday test), the acute stale-reference case, on the
committed pcap caches (no raw re-parse).

Arms (all share the SAME z-path and JSD path and the SAME baseline-update policy;
they differ only in the middle path of the OR):
  B0        = z v CUSUM     v JSD   (shipped OR ensemble, the baseline to beat)
  CAND      = z v MOVINGREF v JSD   (CUSUM replaced by the moving-reference path)
  MRALONE   = MOVINGREF only        (the path in isolation, for diagnosis)

Operating points (both reported):
  fixed_theta : theta=4.0, CUSUM h=5 sigma            (shipped production op point;
                committed cross-day uninvolved FPR ~61.6%, victim DR ~99.3%)
  calibrated  : per-IP theta / CUSUM-h calibrated on the Friday-morning bridge
                (committed cross-day uninvolved FPR ~31.6%)

MOVINGREF is a conformal path: benign-CALIB s_t (Monday+bridge, after burn-in),
sorted, right-tail split-conformal p-value (run_fpr_conformal.pval); alarm if
p <= alpha_mr. Headline alpha_mr = 0.01 (= the CUSUM calibration target FPR, chosen
a priori, NOT tuned per result); grid {0.005, 0.01, 0.02} reported for transparency.

PRIMARY metric = EPISODE-level FPR (30 s cooldown dedup, run_episode_fpr.collapse_episodes)
on uninvolved IPs, with IP-clustered bootstrap CIs. Per-window FPR/DR reported too.
DR guardrail = per-window victim DR (must not materially regress vs B0); MRALONE DR is
reported to expose the sustained-flood self-contamination risk.

Deterministic. Output: experiment/results/movingref_ab_results.json
"""
import os, sys, json, time, copy
import numpy as np
sys.path.insert(0, os.path.dirname(__file__))
from datetime import datetime, timezone

from config import (RESULTS_DIR, THETA_INIT, CUSUM_H_MULT, T_MIN_TIERS,
                    SINGLE_TIER_HIGH_Z_MULT)
from baselines import ThreeTierBaseline
from detectors import CUSUMDetector, LogZDetector, JSDDetector
from feature_filter import filter_active, PRODUCTION_39_FEATURES
from pipeline import (calibrate_threshold, calibrate_cusum_h,
                      upgrade_dst_port_density_inplace)
from run_cicids2017_pcap import (MONDAY_FEATURES_JSON, FRIDAY_FEATURES_JSON,
                                 MIN_ROWS_PER_IP, MIN_ATTACK_WINDOWS_FOR_DR, epoch_to_dt)
from run_episode_fpr import collapse_episodes, COOLDOWN
from run_fpr_conformal import pval
from movingref_detector import MovingRefDetector, CARD_LOG_FEATURES

# ---- MOVINGREF hyperparameters (documented, fixed a priori) -----------------
MR_D          = int(os.environ.get('MR_D', '256'))
MR_ALPHA_FAST = float(os.environ.get('MR_ALPHA_FAST', '0.10'))   # ~10-window (10 s) memory
MR_ALPHA_SLOW = float(os.environ.get('MR_ALPHA_SLOW', '0.02'))   # ~50-window (50 s) memory
MR_SEED       = int(os.environ.get('MR_SEED', '1234'))
MR_BURNIN     = int(os.environ.get('MR_BURNIN', '200'))
ALPHA_MR_GRID = [0.005, 0.01, 0.02]
ALPHA_MR_HEAD = 0.01     # headline (= CUSUM calibrate target FPR); not tuned per result

MAX_UNINV = int(os.environ.get('MR_MAX_UNINV', '150'))   # deterministic cap; 0 = all
OUT = os.path.join(os.path.dirname(__file__), 'movingref_ab_results.json')  # negatives/ (audit trail)

MIN_BENIGN_UNINV = 30


def z_fired(bl, row, dt, theta):
    """Replica of run_fpr_mitigation.per_path's z-path decision (no state mutation)."""
    zs = bl.z_scores(row, dt)
    tiers = 0; zmax = 0.0
    for tk in ('t1', 't2', 't3'):
        d = zs.get(tk)
        if not d:
            continue
        vals = [abs(v) for v in d.values() if v is not None]
        if not vals:
            continue
        tm = max(vals)
        if tm >= theta:
            tiers += 1
        zmax = max(zmax, tm)
    return (tiers >= T_MIN_TIERS) or (tiers >= 1 and zmax >= theta * SINGLE_TIER_HIGH_Z_MULT)


def run_arm(test_rows, bl, cusum, logz, jsd, theta, use_cusum, mr_alarm):
    """One test pass. Returns (det_seq, atk_seq, times). Baseline-update policy
    matches run_cicids2017_pcap: update the z-baseline only on benign non-detections."""
    det_seq = []; atk_seq = []; times = []
    for i, r in enumerate(test_rows):
        dt = r['_dt']; is_atk = bool(r.get('_is_attack'))
        zf = z_fired(bl, r, dt, theta)
        c_alarm = False
        if use_cusum:
            c_alarm, _ = cusum.update(r, bl, dt)
        logz.update(r, theta)          # warm-up parity only (inert)
        j_alarm, _ = jsd.update_and_check(r)
        m_alarm = bool(mr_alarm[i]) if mr_alarm is not None else False
        det = bool(zf or c_alarm or j_alarm or m_alarm)
        det_seq.append(det); atk_seq.append(is_atk); times.append(r['_ts'])
        if not det and not is_atk:
            bl.update(r, dt)
    return det_seq, atk_seq, times


def auc(scores, labels):
    """ROC-AUC via Mann-Whitney rank sum. labels: 1=attack, 0=benign."""
    s = np.asarray(scores, dtype=float); y = np.asarray(labels, dtype=int)
    pos = s[y == 1]; neg = s[y == 0]
    if len(pos) == 0 or len(neg) == 0:
        return None
    order = np.argsort(s, kind='mergesort')
    ranks = np.empty(len(s), dtype=float)
    ranks[order] = np.arange(1, len(s) + 1)
    # average ranks for ties
    _, inv, counts = np.unique(s, return_inverse=True, return_counts=True)
    csum = np.cumsum(counts)
    start = csum - counts
    avg = (start + csum + 1) / 2.0
    ranks = avg[inv]
    r_pos = ranks[y == 1].sum()
    u = r_pos - len(pos) * (len(pos) + 1) / 2.0
    return float(u / (len(pos) * len(neg)))


def cluster_ci_rate(units, nb=2000, seed=7, scale=100.0):
    """IP-clustered bootstrap CI for a pooled ratio num/den. units: list of (num, den).
    scale=100.0 -> percentage (FPR/DR); scale=1.0 -> raw ratio (episodes per IP-day)."""
    if not units:
        return None
    import random as _rnd
    rng = _rnd.Random(seed); m = len(units); rates = []
    for _ in range(nb):
        num = den = 0.0
        for _ in range(m):
            a, b = units[rng.randrange(m)]; num += a; den += b
        if den:
            rates.append(scale * num / den)
    if not rates:
        return None
    rates.sort()
    return [round(rates[int(0.025 * len(rates))], 3), round(rates[int(0.975 * len(rates))], 3)]


def episode_stats(uninv_arm):
    """uninv_arm: list of (times, det_seq) over uninvolved (all-benign) IPs.
    Returns per-window FPR + episode-level FPR with IP-clustered CIs."""
    win_units = []      # (fp_windows, n_windows)
    epi_units = []      # (n_episodes, ip_days)
    tot_win = tot_fp = tot_epi = 0
    ip_days_tot = 0.0; epi_per_ip = []
    for times, det in uninv_arm:
        n = len(det); fp = int(sum(det))
        tot_win += n; tot_fp += fp
        eps = collapse_episodes(times, det, cooldown=COOLDOWN)
        ne = len(eps)
        tot_epi += ne; epi_per_ip.append(ne)
        if times:
            span = (max(times) - min(times)) / 86400.0
            ipd = span if span > 0 else (n / 86400.0)
        else:
            ipd = 0.0
        ip_days_tot += ipd
        win_units.append((fp, n))
        epi_units.append((ne, ipd))
    return {
        'n_ips': len(uninv_arm),
        'per_window_fpr_pct': round(100.0 * tot_fp / tot_win, 2) if tot_win else None,
        'per_window_fpr_cluster_ci': cluster_ci_rate(win_units),
        'total_benign_windows': tot_win,
        'total_alarm_windows': tot_fp,
        'total_episodes': tot_epi,
        'episodes_per_ip_day': round(tot_epi / ip_days_tot, 3) if ip_days_tot > 0 else None,
        'episodes_per_ip_day_cluster_ci': cluster_ci_rate(epi_units, scale=1.0),
        'mean_episodes_per_ip': round(float(np.mean(epi_per_ip)), 3) if epi_per_ip else 0.0,
        'ip_days_total': round(ip_days_tot, 3),
    }


def paired_diff(uninv_a, uninv_b, nb=2000, seed=11):
    """Paired IP-clustered bootstrap of (arm_b - arm_a) on the SAME uninvolved IPs.
    uninv_x: aligned list of (times, det_seq). Returns Delta episodes/IP-day and
    Delta per-window FPR (pp), each with a 95% CI and a one-sided p (frac resamples
    where arm_b did NOT beat arm_a, i.e. Delta >= 0)."""
    if not uninv_a or len(uninv_a) != len(uninv_b):
        return None
    recs = []   # per IP: (ne_a, ne_b, ipd, fp_a, fp_b, nwin)
    for (ta, da), (tb, db) in zip(uninv_a, uninv_b):
        n = len(da)
        if ta:
            span = (max(ta) - min(ta)) / 86400.0
            ipd = span if span > 0 else (n / 86400.0)
        else:
            ipd = 0.0
        recs.append((len(collapse_episodes(ta, da, cooldown=COOLDOWN)),
                     len(collapse_episodes(tb, db, cooldown=COOLDOWN)),
                     ipd, int(sum(da)), int(sum(db)), n))
    import random as _rnd
    rng = _rnd.Random(seed); m = len(recs)
    d_epi = []; d_fpr = []; n_epi_worse = 0; n_fpr_worse = 0
    for _ in range(nb):
        ea = eb = ipd = fa = fb = nw = 0.0
        for _ in range(m):
            r = recs[rng.randrange(m)]
            ea += r[0]; eb += r[1]; ipd += r[2]; fa += r[3]; fb += r[4]; nw += r[5]
        if ipd > 0:
            de = eb / ipd - ea / ipd
            d_epi.append(de); n_epi_worse += (de >= 0)
        if nw > 0:
            df = 100.0 * (fb - fa) / nw
            d_fpr.append(df); n_fpr_worse += (df >= 0)
    def ci(x):
        if not x:
            return None
        x = sorted(x)
        return [round(x[int(0.025 * len(x))], 3), round(x[int(0.975 * len(x))], 3)]
    # point estimates on the full (unresampled) pool
    ea = sum(r[0] for r in recs); eb = sum(r[1] for r in recs)
    ipd = sum(r[2] for r in recs); fa = sum(r[3] for r in recs)
    fb = sum(r[4] for r in recs); nw = sum(r[5] for r in recs)
    return {
        'delta_episodes_per_ip_day': round((eb - ea) / ipd, 3) if ipd else None,
        'delta_episodes_per_ip_day_ci': ci(d_epi),
        'delta_episodes_one_sided_p_no_improvement': round(n_epi_worse / max(len(d_epi), 1), 4),
        'delta_per_window_fpr_pp': round(100.0 * (fb - fa) / nw, 3) if nw else None,
        'delta_per_window_fpr_pp_ci': ci(d_fpr),
        'delta_fpr_one_sided_p_no_improvement': round(n_fpr_worse / max(len(d_fpr), 1), 4),
    }


def victim_stats(vic_arm):
    """vic_arm: list of (times, det_seq, atk_seq) over victim IP(s).
    Per-window DR + attack-episode coverage/latency."""
    tot_atk = tot_tp = 0
    n_epi = 0; first_latency = []
    for times, det, atk in vic_arm:
        atk = np.array(atk, dtype=bool); det = np.array(det, dtype=bool)
        tot_atk += int(atk.sum()); tot_tp += int((det & atk).sum())
        # episodes over attack-window alarms
        atk_times = [t for t, a in zip(times, atk) if a]
        atk_det = [bool(d) for d, a in zip(det, atk) if a]
        eps = collapse_episodes(atk_times, atk_det, cooldown=COOLDOWN)
        n_epi += len(eps)
        if eps and atk_times:
            first_latency.append(round(eps[0][0] - min(atk_times), 1))
    return {
        'n_victims': len(vic_arm),
        'per_window_dr_pct': round(100.0 * tot_tp / tot_atk, 2) if tot_atk else None,
        'attack_windows': tot_atk,
        'detected_attack_windows': tot_tp,
        'n_attack_alarm_episodes': n_epi,
        'first_alarm_latency_s': first_latency,
    }


def main():
    t0 = time.time()
    print("Loading caches ...")
    mon = json.load(open(MONDAY_FEATURES_JSON))['per_ip_windows']
    fri = json.load(open(FRIDAY_FEATURES_JSON))['per_ip_windows']
    upgrade_dst_port_density_inplace(mon, 'monday')
    upgrade_dst_port_density_inplace(fri, 'friday')

    # active feature set on Monday benign sample
    sample = []
    for rows in mon.values():
        sample.extend(rows[:50])
        if len(sample) >= 5000:
            break
    USED, inert = filter_active(PRODUCTION_39_FEATURES, sample)
    print(f"USED_FEATURES: {len(USED)} active; inert={inert}")

    # attack start from Friday labels
    atk_t = sorted(r['_dt'] for rows in fri.values() for r in rows if r.get('_is_attack'))
    if not atk_t:
        print("NO ATTACK WINDOWS FOUND — blocker."); return
    t_start = atk_t[0]
    t_start_dt = epoch_to_dt(t_start) if isinstance(t_start, (int, float)) else t_start

    common = set(mon) & set(fri)
    eligible = [ip for ip in common
                if len(mon[ip]) >= MIN_ROWS_PER_IP and len(fri[ip]) >= MIN_ROWS_PER_IP]
    eligible.sort()

    # classify victim / uninvolved
    victims = []; uninvolved = []
    for ip in eligible:
        f_rows = fri[ip]
        test_n = [r for r in f_rows
                  if (epoch_to_dt(r['_dt']) if isinstance(r['_dt'], (int, float)) else r['_dt']) >= t_start_dt]
        n_atk = sum(1 for r in test_n if r.get('_is_attack'))
        n_ben = sum(1 for r in test_n if not r.get('_is_attack'))
        if n_atk >= MIN_ATTACK_WINDOWS_FOR_DR:
            victims.append(ip)
        elif n_atk == 0 and n_ben >= MIN_BENIGN_UNINV:
            uninvolved.append(ip)
    if MAX_UNINV:
        uninvolved = uninvolved[:MAX_UNINV]
    selected = victims + uninvolved
    print(f"victims={len(victims)} ({victims[:3]}), uninvolved(selected)={len(uninvolved)}")

    # per-arm collectors, per operating point
    # arms: B0, CAND at fixed & calibrated; MRALONE (op-independent)
    coll = {
        'fixed':      {'B0': {'u': [], 'v': []}, 'CAND': {'u': [], 'v': []},
                       'NONE': {'u': [], 'v': []}},
        'calibrated': {'B0': {'u': [], 'v': []}, 'CAND': {'u': [], 'v': []},
                       'NONE': {'u': [], 'v': []}},
        'mralone':    {'u': [], 'v': []},
    }
    mr_auc_victim = []

    for n_done, ip in enumerate(selected):
        is_victim = ip in set(victims)
        m_rows = list(mon[ip]); f_rows = list(fri[ip])
        # stamp numeric episode time _ts, then coerce _dt to datetime
        for r in m_rows + f_rows:
            if isinstance(r.get('_dt'), (int, float)):
                r['_ts'] = float(r['_dt'])
                r['_dt'] = epoch_to_dt(r['_dt'])
            elif isinstance(r.get('_dt'), datetime):
                r.setdefault('_ts', r['_dt'].timestamp())
        m_rows.sort(key=lambda r: r.get('_id_time', 0))
        f_rows.sort(key=lambda r: r.get('_id_time', 0))
        bridge = [r for r in f_rows if r['_dt'] < t_start_dt and not r.get('_is_attack')]
        test = [r for r in f_rows if r['_dt'] >= t_start_dt]
        if len(test) < 5:
            continue
        warm = m_rows + bridge

        # ---- warm the z/CUSUM/JSD detectors ----
        bl = ThreeTierBaseline(USED)
        cusum = CUSUMDetector(USED); logz = LogZDetector(USED); jsd = JSDDetector()
        for r in warm:
            bl.update(r, r['_dt'])
            cusum.update(r, bl, r['_dt']); logz.update(r, THETA_INIT); jsd.update_and_check(r)
        for ff in cusum.s_high:
            cusum.s_high[ff] = 0.0; cusum.s_low[ff] = 0.0
        # calibrated op point (bridge or fallback to Monday tail)
        cal_source = bridge if len(bridge) >= 10 else m_rows[-50:]
        theta_cal = calibrate_threshold(cal_source, bl) if len(cal_source) >= 5 else THETA_INIT
        h_cal = calibrate_cusum_h(cal_source, bl, cusum) if len(cal_source) >= 5 else CUSUM_H_MULT

        # ---- fit + warm the MOVINGREF path, calibrate conformal quantile ----
        mr = MovingRefDetector(USED, D=MR_D, alpha_fast=MR_ALPHA_FAST,
                               alpha_slow=MR_ALPHA_SLOW, seed=MR_SEED)
        calib_scores = mr.warm(warm, burnin=MR_BURNIN)
        calib_sorted = np.sort(np.asarray(calib_scores)) if calib_scores else np.array([])
        # MR timeline over test (EWMA advances unconditionally = self-contamination-honest)
        mr_s = np.array([mr.update_score(r) for r in test])
        mr_p = np.array([pval(calib_sorted, s) for s in mr_s])
        mr_alarm = {a: (mr_p <= a) for a in ALPHA_MR_GRID}
        mr_alarm_head = mr_alarm[ALPHA_MR_HEAD]

        # victim AUC of the raw MR statistic (diagnostic)
        if is_victim:
            labs = [1 if r.get('_is_attack') else 0 for r in test]
            a = auc(mr_s, labs)
            if a is not None:
                mr_auc_victim.append(a)

        # ---- B0 arms ----
        for opname, theta, hmult in (('fixed', THETA_INIT, CUSUM_H_MULT),
                                     ('calibrated', theta_cal, h_cal)):
            bl_b = copy.deepcopy(bl)
            cu_b = copy.deepcopy(cusum); cu_b.h_mult = hmult
            lz_b = copy.deepcopy(logz); js_b = copy.deepcopy(jsd)
            det, atk, times = run_arm(test, bl_b, cu_b, lz_b, js_b, theta,
                                      use_cusum=True, mr_alarm=None)
            if is_victim:
                coll[opname]['B0']['v'].append((times, det, atk))
            else:
                coll[opname]['B0']['u'].append((times, det))

        # ---- CAND arms (headline alpha_mr) ----
        for opname, theta in (('fixed', THETA_INIT), ('calibrated', theta_cal)):
            bl_c = copy.deepcopy(bl)
            lz_c = copy.deepcopy(logz); js_c = copy.deepcopy(jsd)
            det, atk, times = run_arm(test, bl_c, None, lz_c, js_c, theta,
                                      use_cusum=False, mr_alarm=mr_alarm_head)
            if is_victim:
                coll[opname]['CAND']['v'].append((times, det, atk))
            else:
                coll[opname]['CAND']['u'].append((times, det))

        # ---- NONE arms (z v JSD only; bounds the achievable middle-path improvement) ----
        for opname, theta in (('fixed', THETA_INIT), ('calibrated', theta_cal)):
            bl_n = copy.deepcopy(bl)
            lz_n = copy.deepcopy(logz); js_n = copy.deepcopy(jsd)
            det, atk, times = run_arm(test, bl_n, None, lz_n, js_n, theta,
                                      use_cusum=False, mr_alarm=None)
            if is_victim:
                coll[opname]['NONE']['v'].append((times, det, atk))
            else:
                coll[opname]['NONE']['u'].append((times, det))

        # ---- MRALONE (op-independent) ----
        times = [r['_ts'] for r in test]
        det_alone = [bool(x) for x in mr_alarm_head]
        atk_seq = [bool(r.get('_is_attack')) for r in test]
        if is_victim:
            coll['mralone']['v'].append((times, det_alone, atk_seq))
        else:
            coll['mralone']['u'].append((times, det_alone))

        if (n_done + 1) % 25 == 0:
            print(f"  [{n_done+1}/{len(selected)}] elapsed={time.time()-t0:.0f}s")

    # ---- aggregate ----
    out = {
        'metadata': {
            'dataset': 'CIC-IDS-2017 cross-day per-IP (Monday train -> Friday test)',
            'target': 'acute stale-reference case; committed pcap caches (no raw re-parse)',
            'movingref_params': {'D': MR_D, 'alpha_fast': MR_ALPHA_FAST,
                                 'alpha_slow': MR_ALPHA_SLOW, 'seed': MR_SEED,
                                 'burnin': MR_BURNIN, 'sigma': 'median heuristic (benign-train)',
                                 'log1p_features': list(CARD_LOG_FEATURES)},
            'alpha_mr_headline': ALPHA_MR_HEAD, 'alpha_mr_grid': ALPHA_MR_GRID,
            'cooldown_s': COOLDOWN, 'used_features': len(USED),
            'n_victims': len(victims), 'n_uninvolved_selected': len(uninvolved),
            'max_uninv_cap': MAX_UNINV, 'runtime_s': None,
        },
        'results': {},
        'diagnostics': {
            'mralone_victim_mr_statistic_auc': [round(x, 3) for x in mr_auc_victim],
            'auc_note': 'AUC of the raw MR change-statistic s_t discriminating attack vs '
                        'benign windows on the victim; ensemble ROC-AUC out of scope. The 0.882 '
                        'reference is a per-victim ensemble mean across 13 cases, not directly comparable.',
        },
    }
    for opname in ('fixed', 'calibrated'):
        out['results'][opname] = {
            'B0': {'uninvolved_episode_fpr': episode_stats(coll[opname]['B0']['u']),
                   'victim_dr': victim_stats(coll[opname]['B0']['v'])},
            'CAND': {'uninvolved_episode_fpr': episode_stats(coll[opname]['CAND']['u']),
                     'victim_dr': victim_stats(coll[opname]['CAND']['v'])},
            'NONE_z_or_jsd': {'uninvolved_episode_fpr': episode_stats(coll[opname]['NONE']['u']),
                              'victim_dr': victim_stats(coll[opname]['NONE']['v']),
                              'note': 'middle path removed (z v JSD); bounds any middle-path swap'},
            'paired_CAND_minus_B0': paired_diff(coll[opname]['B0']['u'], coll[opname]['CAND']['u']),
            'paired_CAND_minus_NONE': paired_diff(coll[opname]['NONE']['u'], coll[opname]['CAND']['u']),
        }
    out['results']['MRALONE'] = {
        'uninvolved_episode_fpr': episode_stats(coll['mralone']['u']),
        'victim_dr': victim_stats(coll['mralone']['v']),
        'note': 'operating-point-independent (pure conformal MR path at headline alpha_mr)',
    }
    out['metadata']['runtime_s'] = round(time.time() - t0, 1)

    json.dump(out, open(OUT, 'w'), indent=2)
    print("\n================ SUMMARY ================")
    for opname in ('fixed', 'calibrated'):
        for arm in ('B0', 'CAND', 'NONE_z_or_jsd'):
            u = out['results'][opname][arm]['uninvolved_episode_fpr']
            v = out['results'][opname][arm]['victim_dr']
            print(f"[{opname:10s} {arm:13s}] epi/IP/day={u['episodes_per_ip_day']} "
                  f"(CI {u['episodes_per_ip_day_cluster_ci']})  "
                  f"win-FPR={u['per_window_fpr_pct']}%  victim win-DR={v['per_window_dr_pct']}%")
        pd = out['results'][opname]['paired_CAND_minus_B0']
        print(f"   -> paired(CAND-B0):   Depi/IP/day={pd['delta_episodes_per_ip_day']} "
              f"CI{pd['delta_episodes_per_ip_day_ci']} p(no-improve)={pd['delta_episodes_one_sided_p_no_improvement']}"
              f" | Dwin-FPR={pd['delta_per_window_fpr_pp']}pp CI{pd['delta_per_window_fpr_pp_ci']}")
        pn = out['results'][opname]['paired_CAND_minus_NONE']
        print(f"   -> paired(CAND-NONE): Depi/IP/day={pn['delta_episodes_per_ip_day']} "
              f"CI{pn['delta_episodes_per_ip_day_ci']}"
              f" | Dwin-FPR={pn['delta_per_window_fpr_pp']}pp CI{pn['delta_per_window_fpr_pp_ci']}  "
              f"(MOVINGREF's net value over dropping the middle path)")
    ma = out['results']['MRALONE']
    print(f"[MRALONE          ] epi/IP/day={ma['uninvolved_episode_fpr']['episodes_per_ip_day']} "
          f"win-FPR={ma['uninvolved_episode_fpr']['per_window_fpr_pct']}%  "
          f"victim win-DR={ma['victim_dr']['per_window_dr_pct']}%  "
          f"MR-stat AUC(victim)={out['diagnostics']['mralone_victim_mr_statistic_auc']}")
    print(f"Saved: {OUT}  ({out['metadata']['runtime_s']}s)")


if __name__ == '__main__':
    main()
