"""Innovation (one-step EWMA forecast-error) detection path — scores SURPRISE, not LEVEL.

Motivation (from the AnEWMA analysis): the level z-path z=(x-mu)/sigma fires on benign bursts because
their LEVEL is high vs baseline, even when the burst ramps smoothly and is entirely predictable. The
AnEWMA competitor scores the one-step forecast error gamma_t = |x_t - Z_{t-1}| against a slow EWMA
forecast Z, standardized by the benign residual mean/std — a smooth benign ramp is low-surprise (gamma
small -> no alarm) while an abrupt DDoS onset is high-surprise (gamma large -> alarm). On CIC-IDS-2017
AnEWMA's victim ROC-AUC (0.944) beats the level z-path (0.881), so the separation signal is real.

This packages that statistic as a streaming path that plugs into the conformal ensemble exactly like
the z/CUSUM/JSD paths: fit on benign warm, emit a per-window scalar, conformal-calibrate on benign.
Faithful to anewma.py (same lambda, same variance floor); the only change is use as a conformal path
and (optionally) as a drop-in REPLACEMENT for the level z-path.

Training-free: Gamma-bar/Sigma and the EWMA forecast are fit on benign rows only. Deterministic.
"""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))
from baselines import _log_xform   # identical cardinality log transform to the z-path

ANEWMA_LAMBDA = 0.01               # slow forecast: does not "catch up" to a sustained attack


class InnovationPath:
    """Per-context one-step EWMA forecast-error path. score = max_f (gamma_f - gbar_f)/gstd_f."""

    def __init__(self, used_features, lam=ANEWMA_LAMBDA):
        self.feats = list(used_features)
        self.lam = float(lam)
        self.Z = {}            # EWMA forecast state per feature (Z_{t-1})
        self.gbar = {}         # benign residual mean per feature
        self.gstd = {}         # benign residual std (variance-floored) per feature
        self.ok = False

    def fit(self, warm_rows):
        """Fit on benign warm rows. Returns the SORTED benign calibration scores (for conformal pval).

        Single pass: run the EWMA recursion, collect per-feature residuals (for gbar/gstd) and the
        per-window residual vectors (to standardize into calibration scores once gbar/gstd are known).
        Leaves self.Z at the warm-end state so test scoring continues the recursion.
        """
        lam = self.lam
        Z = {}
        resid = {f: [] for f in self.feats}
        feat_abs_sum = {f: 0.0 for f in self.feats}
        feat_n = {f: 0 for f in self.feats}
        gammas = []            # per warm window: {f: gamma or None}
        for r in warm_rows:
            gvec = {}
            for f in self.feats:
                x = _log_xform(f, float(r.get(f, 0.0) or 0.0))
                feat_abs_sum[f] += abs(x); feat_n[f] += 1
                if f not in Z:
                    Z[f] = x; gvec[f] = None          # Z_0 = first obs; no residual
                else:
                    g = abs(x - Z[f])
                    resid[f].append(g); gvec[f] = g
                    Z[f] = lam * x + (1.0 - lam) * Z[f]
            gammas.append(gvec)

        for f in self.feats:
            rs = resid[f]
            if rs:
                m = sum(rs) / len(rs)
                if len(rs) > 1:
                    var = sum((v - m) ** 2 for v in rs) / (len(rs) - 1)
                    sd = var ** 0.5
                else:
                    sd = 0.0
            else:
                m = 0.0; sd = 0.0
            self.gbar[f] = m
            # variance floor identical to anewma.py / baselines.py: 2% of benign scale when scale>50
            feat_scale = feat_abs_sum[f] / feat_n[f] if feat_n[f] else 0.0
            floor = (feat_scale * 0.02) if feat_scale > 50.0 else 1.0
            self.gstd[f] = sd if sd > floor else floor

        self.Z = Z
        self.ok = len(self.feats) > 0 and any(feat_n[f] > 1 for f in self.feats)
        calib = []
        for gvec in gammas:
            vals = [(gvec[f] - self.gbar[f]) / self.gstd[f] for f in self.feats if gvec[f] is not None]
            calib.append(max(vals) if vals else 0.0)
        return sorted(calib)

    def score(self, row):
        """One-step forecast-error score for a window; advances the EWMA forecast (online)."""
        if not self.ok:
            return 0.0
        lam = self.lam
        vals = []
        for f in self.feats:
            x = _log_xform(f, float(row.get(f, 0.0) or 0.0))
            if f in self.Z:
                g = abs(x - self.Z[f])
                self.Z[f] = lam * x + (1.0 - lam) * self.Z[f]
                vals.append((g - self.gbar[f]) / self.gstd[f])
            else:
                self.Z[f] = x
        return max(vals) if vals else 0.0


def innov_scores(train, test, feats):
    """ROC-AUC-harness wrapper (mirrors streaming_baselines `*_scores`): fit on benign train, score
    test (recursion continues from train end). Caller scores benign-before-attack so a sustained
    attack cannot poison the forecast state."""
    import numpy as np
    ip = InnovationPath(feats)
    ip.fit([r for r in train if not r.get('_is_attack')])
    return np.array([ip.score(r) for r in test])
