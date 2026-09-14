import math, copy, random, time
import numpy as np
from datetime import datetime, timezone, timedelta
from config import *
from data_loader import load_corpus, build_split, load_per_ip, AVAILABLE_FEATURES
from baselines import ThreeTierBaseline
from detectors import CUSUMDetector, LogZDetector, JSDDetector, AdaptiveThreshold, compute_confidence
from attack_synthesizer import synthesize, make_slow_ramp

ATTACK_TYPES = ['syn_flood', 'udp_flood', 'dns_amplification', 'ntp_amplification',
                'slowloris', 'fragment_flood', 'pulse_attack', 'carpet_bomb',
                'slow_ramp_5', 'slow_ramp_20']

# ---------------------------------------------------------------------------
# Cache-upgrade helpers (F-CIC-6 fix, 2026-06-03)
# ---------------------------------------------------------------------------

def upgrade_dst_port_density_inplace(per_ip_windows, label=None):
    """Upgrade pre-fix dst_port_density caches to the C-canonical x1000 scale.

    Production formula (layer1/interlayer/shared_memory.c:577): unique_dst_ports
    * 1000 / packets_per_sec. Prior Python pcap extractor lacked the x1000.
    Pre-fix max value is bounded by unique_dst_ports / packets_per_sec <= 256
    (typical TCP/UDP port count), so a global-max < 500 implies pre-fix-scale.
    Mutates per_ip_windows in place and prints which case fired.
    """
    max_v = 0.0
    for rows in per_ip_windows.values():
        for r in rows:
            v = r.get('dst_port_density', 0.0) or 0.0
            if v > max_v:
                max_v = v
    tag = f"[F-CIC-6] {label}: " if label else "[F-CIC-6] "
    if max_v < 500.0:
        for rows in per_ip_windows.values():
            for r in rows:
                if r.get('dst_port_density') is not None:
                    r['dst_port_density'] = r['dst_port_density'] * 1000.0
        print(f"  {tag}pre-fix cache (max={max_v:.2f}) — upgraded ×1000 to match C")
    else:
        print(f"  {tag}cache already post-fix (max={max_v:.2f}) — no upgrade needed")


# ---------------------------------------------------------------------------
# Statistical helpers
# ---------------------------------------------------------------------------

def wilson_ci(s, n, z=1.96):
    if n == 0:
        return (0.0, 1.0)
    p = s / n
    denom = 1 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    margin = (z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))) / denom
    return (max(0.0, center - margin), min(1.0, center + margin))


def mcnemar_p(a_results, b_results):
    b = sum(1 for x, y in zip(a_results, b_results) if x and not y)
    c = sum(1 for x, y in zip(a_results, b_results) if not x and y)
    if b + c == 0:
        return 1.0
    chi2 = (abs(b - c) - 1) ** 2 / (b + c)
    p = math.erfc(math.sqrt(chi2 / 2))
    # erfc underflows to a literal 0.0 for large chi2, which is mathematically
    # impossible to report. Floor at the smallest positive double so the JSON
    # never shows p=0.0; downstream reporting states "p < 1e-300" / "p < 1e-3".
    # NOTE: this window-level test is pseudoreplicated (windows are autocorrelated
    # within an IP); the IP-clustered bootstrap p-value is the trustworthy one.
    return max(p, 5e-324)


def cluster_bootstrap_reduction(per_ip_fp1_fp3_n, n_boot=2000, seed=20260519):
    """IP-clustered significance for the single-tier vs three-tier FPR reduction.

    Resamples IPs (the independent unit) with replacement and recomputes the
    aggregate single/three-tier FPR each time. Returns the relative-reduction
    point estimate, its 95% CI, and a one-sided bootstrap p-value = fraction of
    resamples in which three-tier did NOT reduce FPR (reduction <= 0). This
    replaces the pseudoreplicated window-level McNemar for the headline claim."""
    if not per_ip_fp1_fp3_n:
        return {'reduction_pct': 0.0, 'ci_pct': [0.0, 0.0], 'p_value': 1.0}
    rng = random.Random(seed)
    m = len(per_ip_fp1_fp3_n)
    reductions = []
    n_not_reduced = 0
    for _ in range(n_boot):
        f1 = f3 = nn = 0
        for _ in range(m):
            a, b, c = per_ip_fp1_fp3_n[rng.randrange(m)]
            f1 += a; f3 += b; nn += c
        if nn == 0:
            continue
        r1 = f1 / nn; r3 = f3 / nn
        red = (r1 - r3) / r1 * 100 if r1 > 0 else 0.0
        reductions.append(red)
        if r3 >= r1:
            n_not_reduced += 1
    reductions.sort()
    n = len(reductions)
    return {
        'reduction_pct': round(sum(reductions) / n, 1) if n else 0.0,
        'ci_pct': [round(reductions[int(0.025 * n)], 1),
                   round(reductions[int(0.975 * n)], 1)] if n else [0.0, 0.0],
        'p_value': round(max(n_not_reduced / n, 1.0 / n_boot), 6) if n else 1.0,
        'n_ips': m,
    }


# ---------------------------------------------------------------------------
# Baseline-update gates
# ---------------------------------------------------------------------------
#
# Each runner previously inlined its own (not det) / (not is_attack)
# gate, leading to inconsistencies across the harness (PCAP runners used
# the conjunction gate; CESNET adaptive 3v1 didn't gate at all; pipeline's
# frozen-audit path never updated). This module-level helper makes the
# choice explicit per call-site by name so it is clear which
# regime each runner uses.
#
# The four regimes:
#   FROZEN_AUDIT       -- baseline never updates during test (Table 2 frozen)
#   CONJUNCTION_BENIGN -- (not det) AND (not is_attack); PCAP runner default
#   PRODUCTION_EPISODE -- (not det); mirrors C layer2.c:1700-1704 per-IP gate
#                        (update unless this IP is per-IP anomalous)
#   ATTACK_SKIP        -- update on benign rows only, regardless of detection;
#                        used for offline benign-only calibration passes

class UpdateRegime:
    FROZEN_AUDIT       = 'frozen-audit'
    CONJUNCTION_BENIGN = 'conjunction-benign'
    PRODUCTION_EPISODE = 'production-episode'
    ATTACK_SKIP        = 'attack-skip'


def should_update_baseline(det, is_attack, frozen=False,
                           regime=UpdateRegime.CONJUNCTION_BENIGN):
    """Canonical baseline-update decision. Each runner should declare its
    regime explicitly at the call site so the choice is auditable.

    Args:
        det:       did the detector fire on this row
        is_attack: ground-truth attack label
        frozen:    is the baseline currently frozen (poison protection)
        regime:    one of UpdateRegime.* -- see docstring at top of section
    """
    if frozen:
        return False
    if regime == UpdateRegime.FROZEN_AUDIT:
        return False
    if regime == UpdateRegime.CONJUNCTION_BENIGN:
        return (not det) and (not is_attack)
    if regime == UpdateRegime.PRODUCTION_EPISODE:
        return not det
    if regime == UpdateRegime.ATTACK_SKIP:
        return not is_attack
    raise ValueError(f"unknown UpdateRegime: {regime!r}")


# ---------------------------------------------------------------------------
# Core detection helpers
# ---------------------------------------------------------------------------

def detect_row(row, baseline, cusum, logz, jsd_det, threshold, dt,
               use_cusum=True, use_logz=True, use_jsd=True):
    zs = baseline.z_scores(row, dt)

    tiers_triggered = 0
    z_max = 0.0

    for tier_key in ['t1', 't2', 't3']:
        tier_zs = zs.get(tier_key)
        if tier_zs is None:
            continue
        vals = [abs(v) for v in tier_zs.values() if v is not None]
        if not vals:
            continue
        tier_max = max(vals)
        if tier_max >= threshold:
            tiers_triggered += 1
        z_max = max(z_max, tier_max)

    detected = tiers_triggered >= T_MIN_TIERS
    if not detected and tiers_triggered >= 1 and z_max >= threshold * SINGLE_TIER_HIGH_Z_MULT:
        detected = True

    if use_cusum:
        cusum_alarm, _ = cusum.update(row, baseline, dt)
        if cusum_alarm:
            detected = True

    # NOTE: the standalone log-transform Z-score detector is intentionally NOT a
    # separate ensemble gate. The production C engine has no separate log-z member;
    # it log-transforms the cardinality features (unique_src_ips/dst_ports/flows)
    # INSIDE the main three-tier baseline (baselines.c:259-281), which is now
    # mirrored in ThreeTierBaseline. We still advance the detector's state for
    # warm-up parity, but it no longer contributes an independent detection.
    if use_logz:
        logz.update(row, threshold)

    if use_jsd:
        jsd_alarm, _ = jsd_det.update_and_check(row)
        if jsd_alarm:
            detected = True

    conf = compute_confidence(z_max, tiers_triggered, threshold)
    return detected, z_max, tiers_triggered, conf


def train_baseline(train_rows, use_tier2=True, use_tier3=True):
    bl = ThreeTierBaseline(AVAILABLE_FEATURES, use_tier2=use_tier2, use_tier3=use_tier3)
    for row in train_rows:
        dt = row.get('_dt', datetime(2023, 10, 9, tzinfo=timezone.utc))
        bl.update(row, dt)
    ready_t2 = sum(1 for h in range(24) for f in AVAILABLE_FEATURES
                   if bl.t2 and bl.t2[h][f].ready()) if bl.t2 else 0
    ready_t3 = sum(1 for w in range(168) for f in AVAILABLE_FEATURES
                   if bl.t3 and bl.t3[w][f].ready()) if bl.t3 else 0
    return bl, ready_t2, ready_t3


def calibrate_threshold(calib_rows, baseline, cusum_warm=None, logz_warm=None,
                        jsd_warm=None, target_fpr=CALIB_TARGET_FPR):
    """O(n) percentile-based calibration: find theta at (1-target_fpr) percentile
    of per-row max |z-score| on calib_rows.  Much faster than binary search."""
    if not calib_rows:
        return CALIB_THETA_MIN

    max_zs = []
    for row in calib_rows:
        dt = row.get('_dt', datetime(2023, 10, 9, tzinfo=timezone.utc))
        zs = baseline.z_scores(row, dt)
        vals = []
        for tk in ['t1', 't2', 't3']:
            tzs = zs.get(tk)
            if tzs:
                vals += [abs(v) for v in tzs.values() if v is not None]
        max_zs.append(max(vals) if vals else 0.0)

    if not max_zs:
        return CALIB_THETA_MIN

    pct = (1.0 - target_fpr) * 100.0          # e.g. 97.0 for 3% FPR
    theta = float(np.percentile(max_zs, pct))
    theta = math.ceil(theta * 2) / 2.0
    return round(max(CALIB_THETA_MIN, min(CALIB_THETA_MAX, theta)), 2)


def calibrate_cusum_h(calib_rows, baseline, cusum_warm, target_fpr=0.01):
    """Find CUSUM h_factor multiplier so CUSUM FPR <= target on calib_rows."""
    if not calib_rows:
        return CUSUM_H_MULT

    # Collect peak S_high and S_low values at default h to find distribution
    peak_s = []
    c_test = copy.deepcopy(cusum_warm)
    # Reset accumulators
    for f in c_test.s_high:
        c_test.s_high[f] = 0.0
        c_test.s_low[f] = 0.0

    for row in calib_rows:
        dt = row.get('_dt', datetime(2023, 10, 9, tzinfo=timezone.utc))
        for f in c_test.features:
            x = row.get(f, 0.0)
            # Match the runtime CUSUM path which now uses
            # the immediate (tier-1) baseline (layer2.c:516). Calibrating h
            # against most-mature-tier sigma but running CUSUM against
            # immediate-tier sigma would yield an h-multiplier off the actual
            # operating sigma.
            mu, sigma = baseline.get_immediate_mu_sigma(f)
            k = CUSUM_K_MULT * sigma
            c_test.s_high[f] = max(0.0, c_test.s_high[f] + (x - mu - k))
            c_test.s_low[f]  = max(0.0, c_test.s_low[f]  - (x - mu + k))
            # Record normalised S values (S / sigma)
            if sigma > 0:
                peak_s.append(c_test.s_high[f] / sigma)
                peak_s.append(c_test.s_low[f] / sigma)

    if not peak_s:
        return CUSUM_H_MULT

    # Find h_mult so that fraction of (S/sigma > h_mult) <= target_fpr
    pct = (1.0 - target_fpr) * 100.0
    h_mult = float(np.percentile(peak_s, pct))
    h_mult = math.ceil(h_mult * 2) / 2.0
    return round(max(CUSUM_H_MULT, min(50.0, h_mult)), 2)


def prewarm_detectors(cusum, logz, jsd_det, train_rows, baseline):
    """Run detectors over training rows so their internal state is warm.

    After pre-warming the CUSUM, reset its accumulators to zero.  The point
    of pre-warming is purely to give the baseline enough observations so that
    get_mu_sigma() returns stable estimates.  Carrying over an accumulated
    s_high / s_low from the training period would cause spurious alarms on
    normal test traffic (a traffic regime that naturally differs from the mean
    of the training window triggers the already-primed accumulator immediately).
    """
    for i, row in enumerate(train_rows):
        dt = row.get('_dt', datetime(2023, 10, 9, tzinfo=timezone.utc) + timedelta(hours=i))
        cusum.update(row, baseline, dt)
        logz.update(row, THETA_INIT)
        jsd_det.update_and_check(row)

    # Reset CUSUM accumulators so they start from zero at the test boundary
    for f in cusum.s_high:
        cusum.s_high[f] = 0.0
        cusum.s_low[f] = 0.0


def eval_detection_warmed(test_rows, baseline, cusum, logz, jsd_det,
                          threshold=THETA_INIT,
                          use_cusum=True, use_logz=True, use_jsd=True,
                          update_baseline=True):
    """Run detection over test_rows.

    Baseline-learning model now matches the C engine: the EWMA baseline updates
    EVERY cycle (the production loop calls tier_baseline_update unconditionally;
    only the poisoning detector / attack-state-machine freezes it). It does NOT
    freeze on every detection. This matters with the C-faithful no-reset CUSUM:
    freezing the baseline on detection would let mu go stale and S latch above h
    forever, producing runaway false positives. Letting mu track benign drift lets
    CUSUM's max(0, S + dev - k) decay naturally on benign traffic.

    For DETECTION-RATE (attack) streams the caller passes update_baseline=False so
    the baseline never learns the (unlabeled-in-stream) attack -- a conservative,
    standard offline-eval choice approximating C's attack-state freeze."""
    detections = []
    first_alarm_cycle = None

    for i, row in enumerate(test_rows):
        dt = row.get('_dt', datetime(2023, 10, 9, tzinfo=timezone.utc) + timedelta(hours=i))
        det, z, tiers, conf = detect_row(row, baseline, cusum, logz, jsd_det,
                                         threshold, dt, use_cusum, use_logz, use_jsd)
        detections.append(det)
        if det and first_alarm_cycle is None:
            first_alarm_cycle = i

        # Update EWMA baseline every cycle (poisoning detector is the only freeze).
        if update_baseline and not baseline.frozen:
            baseline.update(row, dt)

    return detections, first_alarm_cycle


def eval_detection(test_rows, is_attack, baseline, threshold=THETA_INIT,
                   use_cusum=True, use_logz=True, use_jsd=True, seed=0):
    """Legacy cold-start eval (kept for Table 4 / backward compat)."""
    cusum = CUSUMDetector(AVAILABLE_FEATURES)
    logz = LogZDetector(AVAILABLE_FEATURES)
    jsd_d = JSDDetector()
    return eval_detection_warmed(test_rows, baseline, cusum, logz, jsd_d,
                                 threshold, use_cusum, use_logz, use_jsd)


# ---------------------------------------------------------------------------
# Per-IP evaluation
# ---------------------------------------------------------------------------

def split_ip_rows(rows):
    """Returns (train_rows, calib_rows, test_rows) using TRAIN/CALIB/TEST fracs."""
    n = len(rows)
    n_train = int(n * TRAIN_FRAC)
    n_calib = int(n * CALIB_FRAC)
    return rows[:n_train], rows[n_train:n_train + n_calib], rows[n_train + n_calib:]


def run_per_ip_evaluation(ip_rows_dict, train_frac=TRAIN_FRAC,
                          use_tier2=True, use_tier3=True,
                          target_normal=6000, attack_samples_per_ip=None):
    """
    For each IP:
      - Train ThreeTierBaseline on first train_frac of rows
      - Pre-warm CUSUM/LogZ/JSD on same training rows
      - Evaluate FPR on held-out (1-train_frac) normal rows
      - Synthesize attack rows from test rows and evaluate DR

    Returns aggregated normal detections and per-attack detections.
    """
    all_normal_dets = []       # bool per test row (True = FP)
    all_attack_dets = {at: [] for at in ATTACK_TYPES}
    calibrated_thetas = []

    ip_list = list(ip_rows_dict.keys())
    n_ips = len(ip_list)
    print(f"  Running per-IP evaluation across {n_ips} IPs "
          f"(train={TRAIN_FRAC} calib={CALIB_FRAC} test={1-TRAIN_FRAC-CALIB_FRAC:.2f}"
          f" use_t2={use_tier2} use_t3={use_tier3})")

    for idx, ip_id in enumerate(ip_list):
        rows = ip_rows_dict[ip_id]
        train_rows, calib_rows, test_rows = split_ip_rows(rows)

        if len(test_rows) < 10:
            continue

        # --- Baseline (train only) ---
        bl, _, _ = train_baseline(train_rows, use_tier2=use_tier2, use_tier3=use_tier3)

        # --- Pre-warm detectors on training rows ---
        cusum = CUSUMDetector(AVAILABLE_FEATURES)
        logz  = LogZDetector(AVAILABLE_FEATURES)
        jsd_d = JSDDetector()
        prewarm_detectors(cusum, logz, jsd_d, train_rows, bl)

        # --- Calibrate z-score theta and CUSUM h (using training-period baseline) ---
        theta  = calibrate_threshold(calib_rows, bl)
        h_mult = calibrate_cusum_h(calib_rows, bl, cusum)
        cusum.h_mult = h_mult
        calibrated_thetas.append(theta)

        # --- Bridge: update baseline on calibration rows so it tracks up to test period ---
        for row in calib_rows:
            dt = row.get('_dt', datetime(2023, 10, 9, tzinfo=timezone.utc))
            bl.update(row, dt)
        # Also run detectors over calibration rows to keep their state current
        for row in calib_rows:
            dt = row.get('_dt', datetime(2023, 10, 9, tzinfo=timezone.utc))
            cusum.update(row, bl, dt)
            logz.update(row, theta)
            jsd_d.update_and_check(row)
        # Reset CUSUM accumulators after bridge period
        for f in cusum.s_high:
            cusum.s_high[f] = 0.0
            cusum.s_low[f] = 0.0

        # --- Normal test (FPR at calibrated thresholds) ---
        cusum_n = copy.deepcopy(cusum)
        logz_n  = copy.deepcopy(logz)
        jsd_n   = copy.deepcopy(jsd_d)
        norm_dets, _ = eval_detection_warmed(
            test_rows, bl, cusum_n, logz_n, jsd_n, threshold=theta)
        all_normal_dets.extend(norm_dets)

        # --- Attack detection (same calibrated thresholds) ---
        for attack_type in ATTACK_TYPES:
            cusum_a = copy.deepcopy(cusum)
            logz_a  = copy.deepcopy(logz)
            jsd_a   = copy.deepcopy(jsd_d)
            n_synth = attack_samples_per_ip or max(40, min(400, len(test_rows)))
            try:
                atk_rows = synthesize(attack_type, test_rows, n_samples=n_synth,
                                      seed=idx * 31 + 7)
            except Exception:
                continue
            atk_dets, _ = eval_detection_warmed(
                atk_rows, bl, cusum_a, logz_a, jsd_a, threshold=theta,
                update_baseline=False)   # don't learn the attack stream
            all_attack_dets[attack_type].extend(atk_dets)

        if (idx + 1) % 10 == 0 or idx == n_ips - 1:
            n_norm = len(all_normal_dets)
            fp_now  = sum(all_normal_dets)
            fpr_now = fp_now / n_norm if n_norm else 0.0
            theta_med = sorted(calibrated_thetas)[len(calibrated_thetas)//2]
            print(f"    [{idx+1}/{n_ips}] cumul_normal={n_norm}  "
                  f"FP={fp_now}  FPR={fpr_now*100:.1f}%  "
                  f"median_theta={theta_med}")

    # Aggregate
    n_normal = len(all_normal_dets)
    fp_total = sum(all_normal_dets)
    fpr = fp_total / n_normal if n_normal else 0.0

    dr_per_attack = {}
    for at, dets in all_attack_dets.items():
        dr_per_attack[at] = sum(dets) / len(dets) if dets else 0.0

    thetas_sorted = sorted(calibrated_thetas)
    n_t = len(thetas_sorted)
    return {
        'fpr': fpr,
        'fp_count': fp_total,
        'n_normal': n_normal,
        'dr_per_attack': dr_per_attack,
        'attack_sample_counts': {at: len(dets) for at, dets in all_attack_dets.items()},
        'theta_median': thetas_sorted[n_t // 2] if n_t else CALIB_THETA_MIN,
        'theta_mean': round(sum(thetas_sorted) / n_t, 2) if n_t else CALIB_THETA_MIN,
        'theta_p25': thetas_sorted[n_t // 4] if n_t else CALIB_THETA_MIN,
        'theta_p75': thetas_sorted[3 * n_t // 4] if n_t else CALIB_THETA_MIN,
        'n_ips_calibrated': n_t,
    }


# ---------------------------------------------------------------------------
# Table 1: Detection Rates (per-IP)
# ---------------------------------------------------------------------------

def run_table1(ip_rows_dict, n_trials=N_TRIALS):
    print("\n=== TABLE 1: Detection Rates (per-IP) ===")

    # Aggregate per-attack detections and per-IP baselines in one pass
    all_attack_dets = {at: [] for at in ATTACK_TYPES}
    all_zscore_dets = {at: [] for at in ATTACK_TYPES}

    ip_list = list(ip_rows_dict.keys())
    n_ips = len(ip_list)

    for trial in range(n_trials):
        print(f"  Trial {trial+1}/{n_trials}")
        for idx, ip_id in enumerate(ip_list):
            rows = ip_rows_dict[ip_id]
            train_rows, calib_rows, test_rows = split_ip_rows(rows)
            if not test_rows:
                continue

            bl, _, _ = train_baseline(train_rows)
            cusum_base = CUSUMDetector(AVAILABLE_FEATURES)
            logz_base  = LogZDetector(AVAILABLE_FEATURES)
            jsd_base   = JSDDetector()
            prewarm_detectors(cusum_base, logz_base, jsd_base, train_rows, bl)
            theta  = calibrate_threshold(calib_rows, bl)
            h_mult = calibrate_cusum_h(calib_rows, bl, cusum_base)
            cusum_base.h_mult = h_mult
            # Bridge: update baseline and detectors on calibration rows
            for row in calib_rows:
                dt = row.get('_dt', datetime(2023, 10, 9, tzinfo=timezone.utc))
                bl.update(row, dt)
                cusum_base.update(row, bl, dt)
                logz_base.update(row, theta)
                jsd_base.update_and_check(row)
            for f in cusum_base.s_high:
                cusum_base.s_high[f] = 0.0
                cusum_base.s_low[f] = 0.0

            n_synth = max(40, min(400 // max(n_ips, 1) + 1, len(test_rows)))

            for attack_type in ATTACK_TYPES:
                try:
                    atk_rows = synthesize(attack_type, test_rows,
                                          n_samples=n_synth,
                                          seed=trial * 100 + idx * 13 + 7)
                except Exception:
                    continue

                # Full ensemble (warmed, calibrated theta)
                c_f = copy.deepcopy(cusum_base)
                l_f = copy.deepcopy(logz_base)
                j_f = copy.deepcopy(jsd_base)
                dets_f, _ = eval_detection_warmed(atk_rows, bl, c_f, l_f, j_f,
                                                  threshold=theta, update_baseline=False)
                all_attack_dets[attack_type].extend(dets_f)

                # Z-score only (warmed, same calibrated theta)
                c_z = copy.deepcopy(cusum_base)
                l_z = copy.deepcopy(logz_base)
                j_z = copy.deepcopy(jsd_base)
                dets_z, _ = eval_detection_warmed(
                    atk_rows, bl, c_z, l_z, j_z, threshold=theta,
                    use_cusum=False, use_logz=False, use_jsd=False, update_baseline=False)
                all_zscore_dets[attack_type].extend(dets_z)

    results = {}
    for attack_type in ATTACK_TYPES:
        full_dets = all_attack_dets[attack_type]
        z_dets = all_zscore_dets[attack_type]
        n_f = len(full_dets); n_z = len(z_dets)
        full_mean = sum(full_dets) / n_f if n_f else 0.0
        z_mean = sum(z_dets) / n_z if n_z else 0.0
        full_ci = wilson_ci(int(full_mean * n_f), n_f)
        z_ci = wilson_ci(int(z_mean * n_z), n_z)
        entry = {
            'full_ensemble_dr': round(full_mean * 100, 1),
            'full_ensemble_ci': [round(full_ci[0] * 100, 1), round(full_ci[1] * 100, 1)],
            'zscore_only_dr': round(z_mean * 100, 1),
            'zscore_only_ci': [round(z_ci[0] * 100, 1), round(z_ci[1] * 100, 1)],
            'n_samples': n_f,
        }
        # Latency placeholder (real latency comes from Table 3)
        if 'ramp' in attack_type:
            entry['latency_cycles'] = None  # filled by Table 3
        results[attack_type] = entry
        print(f"    {attack_type:25s}: DR_full={entry['full_ensemble_dr']}%  "
              f"DR_z={entry['zscore_only_dr']}%  n={n_f}")

    return results


# ---------------------------------------------------------------------------
# Table 2: FPR Single vs Three Tier (per-IP)
# ---------------------------------------------------------------------------

def run_table2_fpr(ip_rows_dict):
    print("\n=== TABLE 2: FPR Single vs Three Tier (per-IP) ===")

    dets_3 = []
    dets_1 = []
    per_ip_fp1_fp3_n = []   # (fp1, fp3, n) per IP -- independent units for clustered significance

    for ip_id, rows in ip_rows_dict.items():
        train_rows, calib_rows, test_rows = split_ip_rows(rows)
        if not test_rows:
            continue

        bl_3, _, _ = train_baseline(train_rows, use_tier2=True,  use_tier3=True)
        bl_1, _, _ = train_baseline(train_rows, use_tier2=False, use_tier3=False)

        # Pre-warm and calibrate for 3-tier
        c3 = CUSUMDetector(AVAILABLE_FEATURES); l3 = LogZDetector(AVAILABLE_FEATURES); j3 = JSDDetector()
        prewarm_detectors(c3, l3, j3, train_rows, bl_3)
        theta3  = calibrate_threshold(calib_rows, bl_3)
        h_mult3 = calibrate_cusum_h(calib_rows, bl_3, c3)
        c3.h_mult = h_mult3

        # Pre-warm and calibrate for 1-tier (same calib rows)
        c1 = CUSUMDetector(AVAILABLE_FEATURES); l1 = LogZDetector(AVAILABLE_FEATURES); j1 = JSDDetector()
        prewarm_detectors(c1, l1, j1, train_rows, bl_1)
        theta1  = calibrate_threshold(calib_rows, bl_1)
        h_mult1 = calibrate_cusum_h(calib_rows, bl_1, c1)
        c1.h_mult = h_mult1

        # Use same theta for fair comparison (max of the two = more conservative)
        theta = max(theta3, theta1)

        # Bridge: update both baselines on calibration rows
        for row in calib_rows:
            dt = row.get('_dt', datetime(2023, 10, 9, tzinfo=timezone.utc))
            bl_3.update(row, dt); bl_1.update(row, dt)
            c3.update(row, bl_3, dt); c1.update(row, bl_1, dt)
            l3.update(row, theta); l1.update(row, theta)
            j3.update_and_check(row); j1.update_and_check(row)
        for f in c3.s_high: c3.s_high[f] = 0.0; c3.s_low[f] = 0.0
        for f in c1.s_high: c1.s_high[f] = 0.0; c1.s_low[f] = 0.0

        ip_fp1 = ip_fp3 = ip_n = 0
        for i, row in enumerate(test_rows):
            dt = row.get('_dt', datetime(2023, 10, 9, tzinfo=timezone.utc) + timedelta(hours=i))
            d3, _, _, _ = detect_row(row, bl_3, c3, l3, j3, theta, dt)
            d1, _, _, _ = detect_row(row, bl_1, c1, l1, j1, theta, dt)
            dets_3.append(d3)
            dets_1.append(d1)
            ip_fp3 += int(d3); ip_fp1 += int(d1); ip_n += 1
        per_ip_fp1_fp3_n.append((ip_fp1, ip_fp3, ip_n))

    fp3 = sum(dets_3); fp1 = sum(dets_1); n = len(dets_3)
    fpr3 = fp3 / n if n else 0.0
    fpr1 = fp1 / n if n else 0.0
    ci3 = wilson_ci(fp3, n); ci1 = wilson_ci(fp1, n)
    rel = (fpr1 - fpr3) / fpr1 * 100 if fpr1 > 0 else 0.0
    p = mcnemar_p(dets_1, dets_3)   # window-level (pseudoreplicated -- see clustered below)
    clustered = cluster_bootstrap_reduction(per_ip_fp1_fp3_n)

    print(f"  1-tier FPR={fpr1*100:.2f}%  3-tier FPR={fpr3*100:.2f}%  "
          f"reduction={rel:.1f}%  n={n}")
    print(f"  window-McNemar p={p:.2e} (pseudoreplicated); "
          f"IP-clustered reduction={clustered['reduction_pct']}% "
          f"CI{clustered['ci_pct']} p={clustered['p_value']:.4g}")
    # Report the window-level p as a string so the JSON never shows 0.0; the
    # trustworthy significance is the IP-clustered bootstrap p-value.
    p_str = f"<1e-300" if p < 1e-300 else f"{p:.3e}"
    return {
        'single_tier_fpr': round(fpr1 * 100, 2),
        'single_tier_ci': [round(ci1[0] * 100, 2), round(ci1[1] * 100, 2)],
        'three_tier_fpr': round(fpr3 * 100, 2),
        'three_tier_ci': [round(ci3[0] * 100, 2), round(ci3[1] * 100, 2)],
        'relative_reduction_pct': round(rel, 1),
        'fp_count_1tier': fp1,
        'fp_count_3tier': fp3,
        'n_normal_samples': n,
        'mcnemar_p_window_pseudoreplicated': p_str,
        'ip_clustered_reduction_pct': clustered['reduction_pct'],
        'ip_clustered_reduction_ci_pct': clustered['ci_pct'],
        'ip_clustered_p_value': clustered['p_value'],
        'n_ips': clustered['n_ips'],
        'significant_clustered': clustered['p_value'] < 0.0125,
    }


# ---------------------------------------------------------------------------
# Table 3: Slow-ramp latency (per-IP, pre-warmed CUSUM)
# ---------------------------------------------------------------------------

def run_table3_latency(ip_rows_dict, n_mc=MONTE_CARLO_TRIALS):
    print("\n=== TABLE 3: Detection Latency (Slow-Ramp, per-IP, pre-warmed) ===")
    results = {}

    ip_list = list(ip_rows_dict.keys())

    for rate, label in [(0.05, '5pct'), (0.10, '10pct'), (0.20, '20pct')]:
        n_cyc = 60 if rate == 0.05 else (40 if rate == 0.10 else 25)
        full_lats = []
        z_lats = []

        for trial in range(n_mc):
            rng = random.Random(trial * 17 + 3)
            ip_id = rng.choice(ip_list)
            rows = ip_rows_dict[ip_id]
            train_rows, calib_rows, test_rows = split_ip_rows(rows)
            if not test_rows:
                full_lats.append(n_cyc)
                z_lats.append(n_cyc)
                continue

            bl, _, _ = train_baseline(train_rows)

            c_f = CUSUMDetector(AVAILABLE_FEATURES)
            l_f = LogZDetector(AVAILABLE_FEATURES)
            j_f = JSDDetector()
            prewarm_detectors(c_f, l_f, j_f, train_rows, bl)
            theta  = calibrate_threshold(calib_rows, bl)
            h_mult = calibrate_cusum_h(calib_rows, bl, c_f)
            c_f.h_mult = h_mult
            # Bridge: update baseline on calibration rows
            for row in calib_rows:
                dt = row.get('_dt', datetime(2023, 10, 9, tzinfo=timezone.utc))
                bl.update(row, dt)
                c_f.update(row, bl, dt)
                l_f.update(row, theta)
                j_f.update_and_check(row)
            for f in c_f.s_high: c_f.s_high[f] = 0.0; c_f.s_low[f] = 0.0

            c_z = copy.deepcopy(c_f)
            l_z = copy.deepcopy(l_f)
            j_z = copy.deepcopy(j_f)

            # Use a calib-period row as ramp base -- baseline is adapted to calib period
            base_row = rng.choice(calib_rows if calib_rows else test_rows)
            ramp = make_slow_ramp(base_row, rate, n_cyc)

            # Latency test: freeze baseline so it doesn't adapt to attack rows
            _, lat_f = eval_detection_warmed(ramp, bl, c_f, l_f, j_f, threshold=theta,
                                              use_cusum=True, use_logz=True, use_jsd=True,
                                              update_baseline=False)
            _, lat_z = eval_detection_warmed(ramp, bl, c_z, l_z, j_z, threshold=theta,
                                              use_cusum=False, use_logz=False, use_jsd=False,
                                              update_baseline=False)

            full_lats.append(lat_f if lat_f is not None else n_cyc)
            z_lats.append(lat_z if lat_z is not None else n_cyc)

        fl = np.array(full_lats, dtype=float)
        zl = np.array(z_lats, dtype=float)
        results[label] = {
            'full_ensemble_median_s': round(float(np.median(fl)), 1),
            'zscore_only_median_s': round(float(np.median(zl)), 1),
            'full_ensemble_iqr': [round(float(np.percentile(fl, 25)), 1),
                                  round(float(np.percentile(fl, 75)), 1)],
            'zscore_only_iqr': [round(float(np.percentile(zl, 25)), 1),
                                 round(float(np.percentile(zl, 75)), 1)],
            'cusum_advantage_s': round(float(np.median(zl)) - float(np.median(fl)), 1),
        }
        print(f"  {rate*100:.0f}%/cycle: full={results[label]['full_ensemble_median_s']} "
              f"z_only={results[label]['zscore_only_median_s']} "
              f"adv={results[label]['cusum_advantage_s']}")
    return results


# ---------------------------------------------------------------------------
# Table 4: Adaptive Threshold (uses global baseline for mixed stream)
# ---------------------------------------------------------------------------

def run_fixed_theta_fpr(ip_rows_dict, theta=THETA_INIT):
    """Per-IP FPR at the FIXED production threshold (no per-IP percentile calibration).

    The shipped C engine runs a fixed theta=4.0 (the adaptive-threshold module
    exists but is not wired into the detection loop); it never computes a per-IP
    calibrated threshold. This reports the operating point the product actually
    uses, and returns per-IP (fp, n) pairs for cluster-robust CIs."""
    per_ip_fp_n = []      # (fp, n) per IP -- the independent units for clustering
    total_fp = 0; total_n = 0
    for ip_id, rows in ip_rows_dict.items():
        train_rows, calib_rows, test_rows = split_ip_rows(rows)
        if len(test_rows) < 10:
            continue
        bl, _, _ = train_baseline(train_rows)
        cusum = CUSUMDetector(AVAILABLE_FEATURES)
        logz = LogZDetector(AVAILABLE_FEATURES)
        jsd_d = JSDDetector()
        prewarm_detectors(cusum, logz, jsd_d, train_rows, bl)
        cusum.h_mult = CUSUM_H_MULT          # fixed h=5sigma, not calibrated
        # bridge baseline through calib rows (detectors run, CUSUM re-zeroed at test start)
        for row in calib_rows:
            dt = row.get('_dt', datetime(2023, 10, 9, tzinfo=timezone.utc))
            bl.update(row, dt); cusum.update(row, bl, dt)
            logz.update(row, theta); jsd_d.update_and_check(row)
        for f in cusum.s_high:
            cusum.s_high[f] = 0.0; cusum.s_low[f] = 0.0
        dets, _ = eval_detection_warmed(test_rows, bl, cusum, logz, jsd_d, threshold=theta)
        fp = sum(dets); n = len(dets)
        per_ip_fp_n.append((fp, n))
        total_fp += fp; total_n += n
    return {
        'theta': theta,
        'fpr_pct': round(total_fp / max(total_n, 1) * 100, 2),
        'fp_count': total_fp,
        'n_normal': total_n,
        'per_ip_fp_n': per_ip_fp_n,
    }


def cluster_bootstrap_fpr(per_ip_fp_n, n_boot=2000, seed=12345):
    """95% CI for aggregate FPR by resampling IPs (the independent unit), not
    windows. Windows within an IP are autocorrelated, so window-level Wilson CIs
    understate uncertainty; clustering by IP is the honest interval."""
    if not per_ip_fp_n:
        return (0.0, 0.0)
    rng = random.Random(seed)
    m = len(per_ip_fp_n)
    rates = []
    for _ in range(n_boot):
        fp = n = 0
        for _ in range(m):
            f, c = per_ip_fp_n[rng.randrange(m)]
            fp += f; n += c
        rates.append(fp / n * 100 if n else 0.0)
    rates.sort()
    lo = rates[int(0.025 * n_boot)]
    hi = rates[int(0.975 * n_boot)]
    return (round(lo, 2), round(hi, 2))


def run_table4_adaptive(ip_rows_dict):
    print("\n=== TABLE 4: Adaptive Threshold (single-IP coherent stream) ===")

    # FIX: the adaptive-threshold demonstration must train AND score on the same
    # IP's profile. Previously the baseline was trained on one IP but scored against
    # a pool of benign rows aggregated from ALL IPs, guaranteeing a cross-profile
    # mismatch and an artifactual ~85% FPR. We now build a single coherent stream
    # from one representative (high-volume) IP: its own benign test rows, a sustained
    # contiguous synthetic attack burst, then benign again -- so detection events have
    # realistic durations and the FP/TP duration classifier behaves as designed.
    rep_ip = max(ip_rows_dict.keys(), key=lambda k: len(ip_rows_dict[k]))
    rows = ip_rows_dict[rep_ip]
    n_train = int(len(rows) * TRAIN_FRAC)
    train_rows = rows[:n_train]
    test_rows = rows[n_train:]
    baseline, _, _ = train_baseline(train_rows)

    # Benign segments come from this IP's own held-out rows; the attack is a single
    # sustained burst synthesized from the same IP (contiguous, so duration >= TP).
    benign_rows = list(test_rows)
    attack_burst = synthesize('syn_flood', test_rows, n_samples=300, seed=1)
    # Coherent stream: benign | sustained attack | benign
    mid = len(benign_rows) // 2
    mixed = ([(r, False) for r in benign_rows[:mid]] +
             [(r, True) for r in attack_burst] +
             [(r, False) for r in benign_rows[mid:]])

    cusum = CUSUMDetector(AVAILABLE_FEATURES)
    logz = LogZDetector(AVAILABLE_FEATURES)
    jsd_d = JSDDetector()
    prewarm_detectors(cusum, logz, jsd_d, train_rows, baseline)
    adapt = AdaptiveThreshold()
    fp_count = 0; tp_count = 0
    n_normal_use = sum(1 for _, a in mixed if not a)
    n_attack_use = sum(1 for _, a in mixed if a)

    for cycle, (row, is_atk) in enumerate(mixed):
        dt = row.get('_dt', datetime(2023, 10, 9, tzinfo=timezone.utc) + timedelta(hours=cycle))
        theta = adapt.get_theta()
        det, z, tiers, conf = detect_row(row, baseline, cusum, logz, jsd_d, theta, dt)
        # Pass wall-clock datetime (not the cycle
        # index) so AdaptiveThreshold's seconds-since-last-eval gating
        # matches the C engine. CESNET hourly callers in particular need
        # this; PCAP runners at 1 Hz worked correctly with cycle indices
        # by accident.
        if det:
            adapt.on_detect(dt)
            if not is_atk:
                fp_count += 1
            else:
                tp_count += 1
        else:
            adapt.on_clear(dt)
        adapt.maybe_adjust(dt)

    n_n = n_normal_use; n_a = n_attack_use
    fpr = fp_count / n_n if n_n else 0.0
    tpr = tp_count / n_a if n_a else 0.0
    return {
        'initial_theta': THETA_INIT,
        'final_theta': round(adapt.theta, 2),
        'n_adjustments': len(adapt.adjustments),
        'fpr': round(fpr * 100, 1),
        'tpr': round(tpr * 100, 1),
        'adjustments': adapt.adjustments,  # full trajectory; was sliced to [:5] of 9
    }


# ---------------------------------------------------------------------------
# Master orchestrator
# ---------------------------------------------------------------------------

def run_all():
    t0 = time.time()
    print("Loading CESNET corpus (per-IP mode)...")
    ip_rows_dict = load_per_ip(TAR_PATH, TIMES_TAR, min_rows=MIN_IP_ROWS_PER_IP)

    if not ip_rows_dict:
        # Fallback: lower threshold or use original flat load + synthetic per-IP split
        print("  WARNING: No IPs met MIN_IP_ROWS_PER_IP threshold; falling back to MIN_IP_ROWS")
        ip_rows_dict = load_per_ip(TAR_PATH, TIMES_TAR, min_rows=MIN_IP_ROWS)

    n_ips = len(ip_rows_dict)
    total_rows = sum(len(v) for v in ip_rows_dict.values())
    print(f"  Loaded {n_ips} IPs, {total_rows} total rows")

    # Collect metadata
    all_test_rows = []
    for rows in ip_rows_dict.values():
        n_train = int(len(rows) * TRAIN_FRAC)
        all_test_rows.extend(rows[n_train:])
    n_train_total = total_rows - len(all_test_rows)

    # --- Table 1 ---
    t1_results = run_table1(ip_rows_dict, n_trials=N_TRIALS)

    # --- Table 2 ---
    t2_results = run_table2_fpr(ip_rows_dict)

    # --- Table 3 ---
    t3_results = run_table3_latency(ip_rows_dict)

    # Patch Table 1 latency from Table 3
    for label, rate_key in [('5pct', 'slow_ramp_5'), ('10pct', None), ('20pct', 'slow_ramp_20')]:
        if rate_key and rate_key in t1_results:
            t1_results[rate_key]['full_latency_median'] = t3_results[label]['full_ensemble_median_s']
            t1_results[rate_key]['full_latency_iqr'] = t3_results[label]['full_ensemble_iqr']
            t1_results[rate_key]['zscore_latency_median'] = t3_results[label]['zscore_only_median_s']

    # --- Table 4 ---
    t4_results = run_table4_adaptive(ip_rows_dict)

    # --- Overall FPR summary (calibrated per-IP theta) ---
    overall = run_per_ip_evaluation(ip_rows_dict)
    fpr_pct = round(overall['fpr'] * 100, 2)
    print(f"\nOverall per-IP FPR (calibrated theta): {fpr_pct}%  (n_normal={overall['n_normal']}, "
          f"fp={overall['fp_count']})")

    # --- Production operating point: FIXED theta=4.0 (what the C engine ships) ---
    fixed = run_fixed_theta_fpr(ip_rows_dict, theta=THETA_INIT)
    print(f"Overall per-IP FPR (fixed theta={THETA_INIT}, production default): "
          f"{fixed['fpr_pct']}%  (n_normal={fixed['n_normal']}, fp={fixed['fp_count']})")
    # Cluster-robust CI (resample IPs, not windows) on the fixed-theta FPR
    fixed_cluster = cluster_bootstrap_fpr(fixed['per_ip_fp_n'])
    print(f"  cluster-bootstrap 95% CI (resampling IPs): "
          f"[{fixed_cluster[0]:.2f}, {fixed_cluster[1]:.2f}]% "
          f"(vs naive window-CI which understates uncertainty)")

    elapsed = time.time() - t0
    print(f"\nTotal runtime: {elapsed:.1f}s")

    return {
        'metadata': {
            'runtime_s': round(elapsed, 1),
            'n_ips': n_ips,
            'total_rows': total_rows,
            'n_train_approx': n_train_total,
            'n_test_normal_approx': len(all_test_rows),
            'available_features': AVAILABLE_FEATURES,
            'n_features_available': len(AVAILABLE_FEATURES),
            'n_features_total_paper': 39,
            'dataset': 'CESNET-TimeSeries24 ip_addresses_sample',
            'evaluation_mode': 'per_ip',
            'train_frac': TRAIN_FRAC,
            'min_ip_rows_per_ip': MIN_IP_ROWS_PER_IP,
        },
        'overall_fpr': {
            'fpr_pct': fpr_pct,
            'fp_count': overall['fp_count'],
            'n_normal': overall['n_normal'],
            'dr_per_attack': {k: round(v * 100, 1) for k, v in overall['dr_per_attack'].items()},
            '_dr_per_attack_note': ('synthetic per-attack DR on CESNET via '
                                    'experiment/attack_synthesizer.py (multiplicative perturbations '
                                    'of real benign rows). DROPPED from paper headlines as circular '
                                    '(CESNET is benign FPR-only; §5.1, §6.13); use the real-attack datasets '
                                    '(CIC-DDoS2019, CIC-IDS-2017/2018, LITNET) for DR claims.'),
            'attack_sample_counts': overall['attack_sample_counts'],
            # Per-IP calibrated-theta distribution across the n_ips_calibrated IPs
            # (surfaced from
            # run_per_ip_evaluation's return value to overall_fpr so a reader
            # of section 6.3 can see whether theta is tightly clustered or sprayed).
            'theta_calib_median': overall.get('theta_median'),
            'theta_calib_mean': overall.get('theta_mean'),
            'theta_calib_p25': overall.get('theta_p25'),
            'theta_calib_p75': overall.get('theta_p75'),
            'theta_calib_n_ips': overall.get('n_ips_calibrated'),
        },
        'production_fixed_theta_fpr': {
            'theta': fixed['theta'],
            'fpr_pct': fixed['fpr_pct'],
            'fp_count': fixed['fp_count'],
            'n_normal': fixed['n_normal'],
            'cluster_bootstrap_ci_pct': list(fixed_cluster),
            'note': 'FPR at the shipped fixed theta=4.0 + h=5sigma (no per-IP calibration). '
                    'cluster CI resamples IPs (independent unit); window-level Wilson CIs '
                    'understate uncertainty due to within-IP autocorrelation.',
        },
        'table1_detection_rates': t1_results,
        '_table1_detection_rates_note': ('synthetic per-attack DR on CESNET (10-trial averaged via '
                                          'experiment/attack_synthesizer.py). DROPPED from paper headlines '
                                          'as circular (CESNET is benign FPR-only; §5.1, §6.13); use the real-attack datasets '
                                          'for DR claims. Differs from overall_fpr.dr_per_attack '
                                          'because of trial-averaging + different seed schedule.'),
        'table2_fpr': t2_results,
        'table3_latency': t3_results,
        'table4_adaptive': t4_results,
    }
