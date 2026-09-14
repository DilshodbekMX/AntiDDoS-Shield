import math, numpy as np
from config import *
from baselines import SlotBaseline

def _kl(p, q, eps=1e-10):
    p = np.maximum(p, eps); q = np.maximum(q, eps)
    p = p / p.sum(); q = q / q.sum()
    return float(np.sum(p * np.log(p / q)))

_LN2 = math.log(2.0)

def jsd(p, q):
    # Normalize by ln(2) so JSD is bounded [0,1], matching C
    # (advanced_detection.c:404: `jsd /= log(2.0)`). Without this, Python returns
    # nats in [0, ln2] and the 0.15 threshold is ~1.44x stricter than C's.
    m = (p + q) / 2.0
    val = (0.5 * _kl(p, m) + 0.5 * _kl(q, m)) / _LN2
    if val < 0.0:
        val = 0.0
    elif val > 1.0:
        val = 1.0
    return val

class CUSUMDetector:
    def __init__(self, feature_names, h_mult=None):
        self.features = [f for f in feature_names if f in CUSUM_FEATURES]
        self.s_high = {f: 0.0 for f in self.features}
        self.s_low  = {f: 0.0 for f in self.features}
        self.counts = {f: 0 for f in self.features}
        self.h_mult = h_mult if h_mult is not None else CUSUM_H_MULT
        # Production-faithful option: keep the running CUSUM sum across alarms
        # (advanced_detection.c never resets). Default False = the offline per-window
        # reset-on-alarm scoring (section 4.3.2). Used by run_fidelity_check.py.
        self.no_reset = False
        # Optional leaky/decaying accumulator: S <- max(0, decay*S + dev). decay=1.0
        # is the standard (non-leaky) CUSUM; decay<1.0 bounds the accumulator so it
        # cannot latch on benign drift while still growing on a sustained attack.
        self.decay = 1.0

    def update(self, row, baseline, dt):
        alarms = {}
        for f in self.features:
            x = row.get(f, 0.0)
            # CUSUM compares against the IMMEDIATE-tier
            # (tier-1) EWMA, mirroring layer2.c:516 which passes only
            # &g_layer2.baselines.immediate into l2_advanced_detect's CUSUM
            # call. The previous get_mu_sigma(f, dt) picked the most mature
            # tier (t3 -> t2 -> t1), making the Python CUSUM faster-responding
            # but less noise-tolerant than the C engine on slow-attack data.
            mu, sigma = baseline.get_immediate_mu_sigma(f)
            k = CUSUM_K_MULT * sigma
            h = self.h_mult * sigma
            self.s_high[f] = max(0.0, self.decay * self.s_high[f] + (x - mu - k))
            self.s_low[f]  = max(0.0, self.decay * self.s_low[f]  - (x - mu + k))
            self.counts[f] += 1
            alarm = False
            if self.counts[f] >= CUSUM_MIN_SAMPLES and h > 0:
                if self.s_high[f] > h or self.s_low[f] > h:
                    alarm = True
                    # OFFLINE-EVAL ADAPTATION (disclosed in paper section 4.3.2): reset
                    # accumulators on alarm so each window is an independent FP/TP
                    # event. The production C engine does NOT reset (advanced_detection.c
                    # :184-194) -- it runs continuously at 1 Hz with a live EWMA baseline,
                    # so mu stays current and max(0, S+dev-k) decays on benign traffic.
                    # In this offline train/test harness the baseline necessarily lags
                    # test-period drift (slow tier-2/3 slots update hourly/weekly), so a
                    # non-reset accumulator latches above h forever and yields ~100% FPR
                    # -- an artifact of the offline split, not of CUSUM. Resetting restores
                    # per-window independence; it is an evaluation-scoring choice, not a
                    # change to the detection logic.
                    if not self.no_reset:
                        self.s_high[f] = 0.0
                        self.s_low[f] = 0.0
            alarms[f] = alarm
        return any(alarms.values()), alarms

class LogZDetector:
    def __init__(self, feature_names):
        self.features = [f for f in feature_names if f in LOGZ_FEATURES]
        self.slots = {f: SlotBaseline(TIER1_ALPHA, TIER1_MIN_SAMPLES) for f in self.features}

    def update(self, row, threshold):
        alarms = {}
        for f in self.features:
            lx = math.log(row.get(f, 0.0) + 1.0)
            z = self.slots[f].z_score(lx)
            self.slots[f].update(lx)
            alarms[f] = (z is not None and abs(z) > threshold)
        return any(alarms.values()), alarms

class JSDDetector:
    """4-component JSD over (tcp, udp, icmp, other) -- matches C production
    (layer2/advanced_detection.c:393-396, threshold 0.15 from layer2_config.h:56)."""
    def __init__(self):
        # Uniform prior across the 4 protocol components
        self.baseline = np.array([0.25, 0.25, 0.25, 0.25])
        self.alpha = JSD_ALPHA          # 0.1, matches jsd_baseline_init in layer2.c:830
        self.min_samples = JSD_MIN_SAMPLES  # 30, matches C readiness gate
        self.count = 0

    def _dist(self, row):
        vals = np.array([
            max(0.0, row.get('tcp_ratio',   0.0)),
            max(0.0, row.get('udp_ratio',   0.0)),
            max(0.0, row.get('icmp_ratio',  0.0)),
            max(0.0, row.get('other_ratio', 0.0)),
        ])
        s = vals.sum()
        if s <= 0:
            return np.array([0.25, 0.25, 0.25, 0.25])
        return vals / s

    def update_and_check(self, row, threshold=JSD_THRESHOLD):
        p = self._dist(row)
        score = jsd(p, self.baseline)
        # EWMA update of the baseline distribution
        self.baseline = self.baseline + self.alpha * (p - self.baseline)
        self.baseline = self.baseline / self.baseline.sum()
        self.count += 1
        # Readiness gate: no alarm until the baseline has matured (C: jsd->ready).
        if self.count < self.min_samples:
            return False, score
        return score > threshold, score

def _epoch_seconds(t):
    """Convert a datetime / epoch-second / cycle-index to float seconds.
    Datetime -> .timestamp(); float/int -> as-is. AdaptiveThreshold callers
    should pass datetime (or a real wall-clock second value) so the
    seconds-since-last-eval gating is accurate. Cycle indices are accepted
    for backward compatibility but will be wrong on non-1Hz streams."""
    if hasattr(t, 'timestamp'):
        return t.timestamp()
    return float(t)


class AdaptiveThreshold:
    """Adaptive threshold controller mirroring layer2/adaptive_threshold.c.

    Uses wall-clock seconds everywhere
    (event durations, evaluation-interval gating, adjustment timestamps).
    The pre-fix version treated the caller's `cycle` integer as both an
    index AND a seconds-since-start value, which silently broke on
    non-1-Hz streams. PCAP runners use 1 Hz windows so they were
    correct by accident; CESNET hourly rows (1 cycle = 3600 s) were
    badly miscalibrated -- the controller thought 300 cycles
    (ADAPTIVE_EVAL_INTERVAL) was 300 s of wall-clock time when it was
    really 1080000 s = 300 hours. Re-evaluation effectively never fired
    on CESNET.

    The C engine uses clock_gettime(CLOCK_MONOTONIC) so durations are
    real wall-clock seconds. This class now does the same via
    datetime.timestamp(). Cycle-index fallback retained so PCAP
    runners (which were already correct on 1 Hz) continue to work
    without modification.
    """

    def __init__(self):
        self.theta = THETA_INIT
        self.events = []          # list of durations in seconds
        self.open_event = None     # epoch-second of the open detection
        self.last_eval = None      # epoch-second of the last evaluation; None until first call
        self.adjustments = []

    def get_theta(self):
        return self.theta

    def on_detect(self, t):
        """Mark a detection at wall-clock time `t` (datetime or epoch sec)."""
        if self.open_event is None:
            self.open_event = _epoch_seconds(t)

    def on_clear(self, t):
        """Mark a clear at wall-clock time `t`; closes the open event window."""
        if self.open_event is not None:
            duration = _epoch_seconds(t) - self.open_event
            self.events.append(duration)
            self.open_event = None

    def maybe_adjust(self, t):
        """Re-evaluate theta if ADAPTIVE_EVAL_INTERVAL seconds have elapsed
        since the last evaluation (wall-clock seconds). Mirrors C
        adaptive_threshold.c:231-260."""
        now = _epoch_seconds(t)
        if self.last_eval is None:
            self.last_eval = now
            return self.theta
        if now - self.last_eval < ADAPTIVE_EVAL_INTERVAL:
            return self.theta
        window = self.events[-ADAPTIVE_WINDOW:] if self.events else []
        if len(window) < ADAPTIVE_MIN_EVENTS:
            self.last_eval = now
            return self.theta
        fp = sum(1 for d in window if d < ADAPTIVE_FP_DURATION)
        tp = sum(1 for d in window if d >= ADAPTIVE_TP_DURATION)
        n = len(window)
        fp_rate = fp / n; tp_rate = tp / n
        old_theta = self.theta
        # Match C exactly (adaptive_threshold.c:231-260):
        #   fp_rate > 0.30           -> increase by step (doubled if fp_rate > 0.50)
        #   fp_rate < 0.10 AND tp_rate > tp_min+0.2 (=0.70) AND theta>theta0
        #                            -> decrease by half a step, floored at theta0
        if fp_rate > ADAPTIVE_FP_RATE_TRIGGER:
            inc = THETA_STEP * (2.0 if fp_rate > 0.50 else 1.0)
            self.theta = min(THETA_MAX, self.theta + inc)
        elif fp_rate < 0.10 and tp_rate > (ADAPTIVE_TP_RATE_TRIGGER + 0.2):
            if self.theta > THETA_INIT:
                self.theta = max(THETA_INIT, self.theta - THETA_STEP * 0.5)
        self.last_eval = now
        if self.theta != old_theta:
            self.adjustments.append({'at_sec': now, 'old': old_theta, 'new': self.theta})
        return self.theta

def compute_confidence(z_max, n_tiers, theta):
    tier_conf = TIER_CONF.get(min(n_tiers, 3), 0.0)
    if tier_conf == 0.0:
        return 0.0
    z_factor = 1.0 + Z_FACTOR_MULT * (z_max - theta) / max(theta, EPS)
    z_factor = min(Z_FACTOR_CAP, max(1.0, z_factor))
    return min(1.0, tier_conf * z_factor)

def get_severity(z_max, n_tiers):
    if n_tiers == 3:
        if z_max >= Z_CRITICAL_3TIER: return 'CRITICAL'
        if z_max >= Z_HIGH_3TIER:     return 'HIGH'
        if z_max >= Z_MEDIUM_3TIER:   return 'MEDIUM'
    elif n_tiers == 2:
        if z_max >= Z_HIGH_2TIER:     return 'HIGH'
        if z_max >= Z_MEDIUM_2TIER:   return 'MEDIUM'
    elif n_tiers == 1:
        if z_max >= Z_MEDIUM_1TIER:   return 'MEDIUM'
    return 'LOW'
