import math
import numpy as np
from config import *

# C-fidelity constants (layer2/baselines.c)
MAX_ZSCORE_CAP = 100.0          # baselines.c:328
VAR_FLOOR_MEAN_THRESHOLD = 50.0  # baselines.c:356
VAR_FLOOR_FRACTION = 0.02        # baselines.c:356 (2% of mean)
PER_FEATURE_READY = 10           # baselines.c:334 (z not computed below 10 samples)

# Cardinality features log-transformed INSIDE the main baseline, matching
# feature_uses_log_transform() in baselines.c:259-263. The log is applied on
# both update and z-score so the baseline lives in log space.
# `unique_flows` is listed for continuity only: it is excluded from the evaluated
# schedule by run_crosscorpus_auc.py::EXCLUDED_DUPLICATE_FEATURES (2026-09-24), so
# active_features() drops the name before _log_xform ever sees it. Left in place so
# this set still describes the pre-exclusion runs the deposited records came from.
LOG_TRANSFORM_FEATURES = {'unique_src_ips', 'unique_dst_ports', 'unique_flows'}


def _log_xform(feature, x):
    return math.log(x + 1.0) if feature in LOG_TRANSFORM_FEATURES else x


class SlotBaseline:
    """Single EWMA slot for one feature. Mirrors feature_baseline_* in baselines.c."""
    __slots__ = ['mean','var','count','alpha','min_samples']

    def __init__(self, alpha, min_samples):
        self.mean = 0.0; self.var = 0.0
        self.count = 0; self.alpha = alpha; self.min_samples = min_samples

    def update(self, x):
        # F2: first-sample initialization matches C (baselines.c:229-232):
        # sample 0 sets mean=value, variance=0 (no EWMA blend with a prior).
        if self.count == 0:
            self.mean = x
            self.var = 0.0
            self.count = 1
            return
        self.count += 1
        delta = x - self.mean
        self.mean += self.alpha * delta
        self.var = (1 - self.alpha) * (self.var + self.alpha * delta * delta)

    def z_score(self, x):
        # Gate: tier-specific min_samples (>= C's fixed per-feature floor of 10;
        # voting-equivalent to C's separate tier-readiness gate).
        if self.count < self.min_samples:
            return None
        # F1: variance bootstrap floor + z cap, matching C (baselines.c:356-367).
        stddev = math.sqrt(self.var) if self.var > 0.0 else 0.0
        min_stddev = (self.mean * VAR_FLOOR_FRACTION) if self.mean > VAR_FLOOR_MEAN_THRESHOLD else 1.0
        if stddev < min_stddev:
            stddev = min_stddev
        z = (x - self.mean) / stddev
        if z > MAX_ZSCORE_CAP:
            z = MAX_ZSCORE_CAP
        elif z < -MAX_ZSCORE_CAP:
            z = -MAX_ZSCORE_CAP
        return z

    def ready(self):
        return self.count >= self.min_samples

class ThreeTierBaseline:
    def __init__(self, feature_names, use_tier2=True, use_tier3=True):
        self.features = feature_names
        self.use_tier2 = use_tier2
        self.use_tier3 = use_tier3
        self.frozen = False

        # Tier 1: 1 global slot
        self.t1 = {f: SlotBaseline(TIER1_ALPHA, TIER1_MIN_SAMPLES) for f in feature_names}
        # Tier 2: 24 hourly slots
        self.t2 = [{f: SlotBaseline(TIER2_ALPHA, TIER2_MIN_SAMPLES) for f in feature_names}
                   for _ in range(TIER2_SLOTS)] if use_tier2 else None
        # Tier 3: 168 weekly slots
        self.t3 = [{f: SlotBaseline(TIER3_ALPHA, TIER3_MIN_SAMPLES) for f in feature_names}
                   for _ in range(TIER3_SLOTS)] if use_tier3 else None

        # Poisoning protection state (mirrors C: layer2/baselines.c:1264-1360)
        self.poison_last_mean = {f: 0.0 for f in feature_names}
        self.poison_window_start = None
        self.poison_large_change_count = 0
        self.poison_detected = False
        # track when poison was detected so update() can
        # auto-unfreeze after BASELINE_POISON_RECOVERY_SEC (matches C
        # layer2.c:660-672 recovery path).
        self.poison_detected_at = None

    def _slots(self, dt):
        h = dt.hour  # 0-23
        w = dt.weekday() * 24 + dt.hour  # 0-167
        return h, w

    def _check_poisoning(self, dt):
        if not POISON_PROTECTION_ENABLED or self.frozen:
            return
        # Window reset
        if self.poison_window_start is None or \
           (dt - self.poison_window_start).total_seconds() > POISON_WINDOW_SEC:
            self.poison_window_start = dt
            self.poison_large_change_count = 0
            for f in self.features:
                self.poison_last_mean[f] = self.t1[f].mean
            return
        # Only check after T1 is FULLY ready (every feature). Mirrors C's
        # `!baselines->immediate.ready` guard -- `tier->ready` becomes true
        # only when every feature's `sample_count >= min_samples_ready`
        # (baselines.c:289-298). (Previously this checked only
        # features[0], which falsely declared the tier ready as soon as the
        # first feature warmed.)
        if not self._tier_all_ready(self.t1):
            for f in self.features:
                self.poison_last_mean[f] = self.t1[f].mean
            return
        # Per-cycle large-change check on key volume features
        large_change = False
        for f in POISON_KEY_FEATURES:
            if f not in self.t1:
                continue
            curr = self.t1[f].mean
            prev = self.poison_last_mean[f]
            self.poison_last_mean[f] = curr  # always advance reference
            if prev < 1.0:
                continue
            if abs(curr - prev) / prev > POISON_CHANGE_RATE_THRESHOLD:
                large_change = True
        if large_change:
            self.poison_large_change_count += 1
            if self.poison_large_change_count >= POISON_COUNT_THRESHOLD:
                self.poison_detected = True
                self.frozen = True
                self.poison_detected_at = dt   # record detection time

    def update(self, row, dt):
        # auto-recover after BASELINE_POISON_RECOVERY_SEC.
        # Mirrors layer2.c:660-672 -- once enough time has elapsed since the
        # poison detection, reset the tracker and unfreeze so the baseline
        # can resume adapting on long-running streams.
        if self.frozen and self.poison_detected_at is not None:
            elapsed = (dt - self.poison_detected_at).total_seconds()
            if elapsed >= BASELINE_POISON_RECOVERY_SEC:
                self.frozen = False
                self.poison_detected = False
                self.poison_detected_at = None
                self.poison_large_change_count = 0
                # Re-seed last_mean references so the next 300s window
                # measures change from the post-recovery state, not the
                # pre-poison state.
                for f in self.features:
                    self.poison_last_mean[f] = self.t1[f].mean
        if self.frozen:
            return
        h, w = self._slots(dt)
        for f in self.features:
            x = _log_xform(f, row.get(f, 0.0))   # F3: log-transform cardinality features
            self.t1[f].update(x)
            if self.t2:
                self.t2[h][f].update(x)
            if self.t3:
                self.t3[w][f].update(x)
        # After update, check for poisoning (will freeze self if triggered)
        self._check_poisoning(dt)

    def _tier_all_ready(self, slot_stats):
        """All-features-ready gate, mirroring layer2/baselines.c:289-298.
        Tier is ready when EVERY feature's _RunningStats has reached
        min_samples_ready. Earlier this method accepted any feature having a
        non-None z, which let tier-2/3 vote before the tier was fully mature."""
        return all(slot_stats[f].ready() for f in self.features)

    def z_scores(self, row, dt):
        """Returns dict: {'t1': {f: z}|None, 't2': {f: z}|None, 't3': {f: z}|None}.
        Every tier (including t1) only contributes when EVERY feature in that
        tier slot is ready -- matches C tier->ready gate (the gate covers t1 as
        well as t2/t3; the C engine's
        `l2_detect_anomaly` calls `tier_baseline_z_scores` which short-circuits
        when `!tier->ready` for the immediate tier the same way it does for
        hourly / weekly)."""
        h, w = self._slots(dt)
        result = {'t1': None, 't2': None, 't3': None}
        if self._tier_all_ready(self.t1):
            result['t1'] = {f: self.t1[f].z_score(_log_xform(f, row.get(f, 0.0)))
                            for f in self.features}
        if self.t2 and self._tier_all_ready(self.t2[h]):
            result['t2'] = {f: self.t2[h][f].z_score(_log_xform(f, row.get(f, 0.0)))
                            for f in self.features}
        if self.t3 and self._tier_all_ready(self.t3[w]):
            result['t3'] = {f: self.t3[w][f].z_score(_log_xform(f, row.get(f, 0.0)))
                            for f in self.features}
        return result

    def get_mu_sigma(self, feature, dt):
        """Returns (mu, sigma) from the most mature tier (t3 -> t2 -> t1).
        Kept for non-CUSUM callers; CUSUM must use get_immediate_mu_sigma()
        to match the C engine."""
        h, w = self._slots(dt)
        if self.t3 and self.t3[w][feature].ready():
            s = self.t3[w][feature]
        elif self.t2 and self.t2[h][feature].ready():
            s = self.t2[h][feature]
        else:
            s = self.t1[feature]
        return s.mean, math.sqrt(s.var)

    def get_immediate_mu_sigma(self, feature):
        """Tier-1 (immediate-EWMA) mu/sigma for CUSUM.

        Matches the C call `l2_advanced_detect(t1, ..., &g_layer2.cusum, ...)`
        at layer2.c:516 where the production engine passes ONLY the immediate
        tier into cusum_detect. The Python harness previously used the
        most-mature tier in get_mu_sigma() above; that produced a faster-
        responding but less-noise-tolerant CUSUM than the C engine.

        Callers: CUSUMDetector.update only. LogZ and other detectors keep
        using get_mu_sigma() because they're not part of the production
        per-IP code path being mirrored here."""
        s = self.t1[feature]
        return s.mean, math.sqrt(s.var)
