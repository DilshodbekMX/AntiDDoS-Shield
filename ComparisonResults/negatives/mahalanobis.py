"""Training-free, per-destination covariance-aware (Mahalanobis) anomaly path for Layer-2.

Spec: experiment/MAHALANOBIS_PROTOTYPE_BRIEF.md. Harness prototype only — not wired into the C
engine. Fits a benign mean mu and a Ledoit-Wolf-shrunk covariance Sigma on benign rows (training-
free), scores d2(x) = (x-mu)^T Sigma^-1 (x-mu). On-manifold benign bursts (correlated features
rising together) ride high-variance directions -> small d2; off-manifold attack structure (e.g. pps
up but flows flat) -> large d2.

Feature-space note (deviation from brief, justified): the brief lists four cardinality features to
log-transform, but the production z-path (`baselines._log_xform`, mirroring baselines.c:259-263) log-
transforms only THREE — unique_src_ips, unique_dst_ports, unique_flows — and NOT dst_port_density.
The brief's stated intent is "match the z-path's in-baseline log transform," so we reuse `_log_xform`
verbatim: M1 then lives in the exact same feature space as the z-path, keeping the A/B fair.
"""
import math
import numpy as np
from sklearn.covariance import LedoitWolf
from baselines import _log_xform  # 3-feature cardinality log transform, identical to the z-path

D2_CAP = 1e6            # cap d2 so a near-singular direction cannot produce inf/overflow
MIN_FIT_FLOOR = 10      # never fit on fewer than this many benign rows


def _vectorize(rows, feats):
    """Build the log-transformed feature matrix over `feats` for a list of row dicts."""
    return np.array(
        [[_log_xform(f, float(r.get(f, 0.0) or 0.0)) for f in feats] for r in rows],
        dtype=float,
    )


class MahalanobisPath:
    """Per-context covariance-aware path. Fit on benign only; score = squared Mahalanobis distance."""

    def __init__(self, d2_cap=D2_CAP):
        self.feats = None
        self.lw = None          # fitted LedoitWolf (holds location_, precision_, shrinkage_)
        self.mu = None
        self.shrinkage = None
        self.d = 0
        self.n_fit = 0
        self.ok = False
        self.d2_cap = d2_cap

    def fit(self, benign_rows, active_features):
        """Fit mu, Ledoit-Wolf Sigma on benign rows only. Returns self; sets .ok.

        Requires >= max(MIN_FIT_FLOOR, 2*d) benign rows (the brief's ~2*d floor); otherwise .ok=False
        and the context is skipped by the caller. No attack labels touch this fit.
        """
        self.feats = list(active_features)
        self.d = len(self.feats)
        X = _vectorize(benign_rows, self.feats)
        self.n_fit = X.shape[0]
        if self.d == 0 or self.n_fit < max(MIN_FIT_FLOOR, 2 * self.d):
            self.ok = False
            return self
        # Ledoit-Wolf shrinkage -> well-conditioned, invertible covariance even when d ~ n_fit.
        self.lw = LedoitWolf(assume_centered=False).fit(X)
        self.mu = self.lw.location_
        self.shrinkage = float(self.lw.shrinkage_)
        self.ok = True
        return self

    def score(self, row):
        """Squared Mahalanobis distance d2 for one row (capped). Larger = more anomalous."""
        if not self.ok:
            return 0.0
        X = _vectorize([row], self.feats)
        return float(min(self.lw.mahalanobis(X)[0], self.d2_cap))

    def score_many(self, rows):
        """Vectorized d2 over a list of rows (capped)."""
        if not self.ok:
            return np.zeros(len(rows), dtype=float)
        X = _vectorize(rows, self.feats)
        return np.minimum(self.lw.mahalanobis(X), self.d2_cap)


def maha_scores(train, test, feats):
    """AUC-arm convenience: fit on benign train rows, return capped d2 over `test` (np.array).

    Mirrors the streaming_baselines `*_scores(train, test, feats)` signature so it drops into the
    existing ROC-AUC harness. Fits on benign-train only (drops any attack-labeled train rows).
    """
    mp = MahalanobisPath()
    mp.fit([r for r in train if not r.get('_is_attack')], feats)
    return mp.score_many(test)
