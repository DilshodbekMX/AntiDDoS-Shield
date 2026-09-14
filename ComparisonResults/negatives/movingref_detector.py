"""Moving-reference change-detection path for Layer-2 (NEWMA / two-timescale RFF-MMD).

HARNESS-ONLY PROTOTYPE (l2-detector-prototyping). This is a candidate drop-in
replacement for the non-resetting CUSUM path inside the OR ensemble
(z v CUSUM v JSD). It is a streaming, buffer-free change detector:

  x_t   : per-window feature vector over the corpus ACTIVE feature set
          (filter_active), with log1p applied to the four cardinality features
          {unique_src_ips, unique_dst_ports, unique_flows, dst_port_density}
          exactly as requested (same family the z-path log-transforms).
  x_std : standardized by benign-TRAIN mean / scale (training-free).
  phi   : Random Fourier Feature map R^d -> R^D approximating a Gaussian kernel,
          FIXED after fit. Bandwidth sigma set by the median heuristic on
          BENIGN-TRAIN standardized vectors only (training-free). Fixed seed.
  z_fast: EWMA of phi with forgetting alpha_fast  (short memory ~ 1/alpha_fast)
  z_slow: EWMA of phi with forgetting alpha_slow  (long  memory ~ 1/alpha_slow)
  s_t   : || z_fast - z_slow ||_2   (NEWMA statistic; large = recent shift)

Memory O(D), work O(D) per window. No packet/window buffer.

NEWMA reference: Keriven, Garreau & Ibnkahla, "NEWMA: a new method for scalable
model-free online change-point detection" (IEEE T-SP 2020). The statistic is the
norm of the difference of two EWMAs of a (random-feature) embedding; alpha_fast >
alpha_slow gives a fast tracker and a slow moving reference. A slow benign drift is
absorbed by BOTH EWMAs and cancels in the difference; an abrupt shift moves z_fast
first and opens the gap.

Turned into a conformal path exactly like the other paths: collect benign-CALIB s_t,
sort, right-tail split-conformal p-value via run_fpr_conformal.pval; alarm if p<=alpha.

Deterministic: all randomness (RFF weights, median-heuristic subsample) is seeded.
"""
import copy
import numpy as np

# The four cardinality features log1p-transformed for the moving-reference vector
# (per the prototype brief: same family the z-path log-transforms, plus dst_port_density).
CARD_LOG_FEATURES = ('unique_src_ips', 'unique_dst_ports', 'unique_flows', 'dst_port_density')


class MovingRefDetector:
    """Two-timescale RFF-EWMA (NEWMA) change statistic, buffer-free."""

    def __init__(self, features, D=256, alpha_fast=0.10, alpha_slow=0.02,
                 seed=1234, median_subsample=400):
        self.features = list(features)
        self.d = len(self.features)
        self.D = int(D)
        self.alpha_fast = float(alpha_fast)
        self.alpha_slow = float(alpha_slow)
        self.seed = int(seed)
        self.median_subsample = int(median_subsample)
        self._card_mask = np.array([f in CARD_LOG_FEATURES for f in self.features], dtype=bool)
        # Fitted params (set in fit_params)
        self.mean = None
        self.scale = None
        self.sigma = None
        self.W = None      # (D, d)
        self.b = None      # (D,)
        self._phi_norm = np.sqrt(2.0 / self.D)
        # Streaming EWMA state
        self.z_fast = None
        self.z_slow = None

    # ------------------------------------------------------------------ raw vec
    def _raw(self, rows):
        """Rows -> (n, d) float matrix with log1p on cardinality features."""
        X = np.empty((len(rows), self.d), dtype=np.float64)
        for i, r in enumerate(rows):
            for j, f in enumerate(self.features):
                X[i, j] = float(r.get(f, 0.0) or 0.0)
        if self._card_mask.any():
            X[:, self._card_mask] = np.log1p(np.maximum(X[:, self._card_mask], 0.0))
        return X

    def _raw_one(self, row):
        v = np.empty(self.d, dtype=np.float64)
        for j, f in enumerate(self.features):
            v[j] = float(row.get(f, 0.0) or 0.0)
        if self._card_mask.any():
            v[self._card_mask] = np.log1p(np.maximum(v[self._card_mask], 0.0))
        return v

    # ------------------------------------------------------------------ fit
    def fit_params(self, warm_rows):
        """Fit standardization mean/scale, median-heuristic sigma, and RFF W/b on
        BENIGN warm rows only (training-free). Does NOT touch EWMA state."""
        X = self._raw(warm_rows)
        self.mean = X.mean(axis=0)
        std = X.std(axis=0)
        # Variance floor: features with ~0 benign spread get unit scale so they
        # neither dominate nor NaN the standardized vector.
        self.scale = np.where(std < 1e-6, 1.0, std)
        Xs = (X - self.mean) / self.scale

        # Median heuristic on a seeded benign subsample.
        rng = np.random.default_rng(self.seed)
        n = Xs.shape[0]
        m = min(n, self.median_subsample)
        idx = rng.choice(n, size=m, replace=False) if n > m else np.arange(n)
        sub = Xs[idx]
        # pairwise Euclidean distances, upper triangle
        diff = sub[:, None, :] - sub[None, :, :]
        d2 = np.einsum('ijk,ijk->ij', diff, diff)
        iu = np.triu_indices(len(sub), k=1)
        dists = np.sqrt(np.maximum(d2[iu], 0.0))
        med = float(np.median(dists)) if dists.size else 0.0
        self.sigma = med if med > 1e-9 else 1.0

        # Gaussian RFF: k(x,y)=exp(-||x-y||^2/(2 sigma^2)) <-> W ~ N(0, 1/sigma^2 I)
        rng2 = np.random.default_rng(self.seed + 1)
        self.W = rng2.standard_normal((self.D, self.d)) / self.sigma
        self.b = rng2.uniform(0.0, 2.0 * np.pi, size=self.D)
        return self

    # ------------------------------------------------------------------ phi
    def _phi_from_std(self, xs):
        return self._phi_norm * np.cos(self.W @ xs + self.b)

    def _phi(self, row):
        xs = (self._raw_one(row) - self.mean) / self.scale
        return self._phi_from_std(xs)

    # ------------------------------------------------------------------ stream
    def reset_state(self):
        self.z_fast = None
        self.z_slow = None

    def update_score(self, row):
        """Advance both EWMAs by one window; return s_t = ||z_fast - z_slow||."""
        phi = self._phi(row)
        if self.z_fast is None:
            self.z_fast = phi.copy()
            self.z_slow = phi.copy()
            return 0.0
        self.z_fast += self.alpha_fast * (phi - self.z_fast)
        self.z_slow += self.alpha_slow * (phi - self.z_slow)
        diff = self.z_fast - self.z_slow
        return float(np.sqrt(diff @ diff))

    def warm(self, warm_rows, burnin=200):
        """Fit params, then stream warm rows to warm the two EWMAs. Returns the
        list of benign s_t AFTER burnin (steady-state) for conformal calibration.
        Leaves the EWMA state at end-of-warm (carried into the test stream)."""
        self.fit_params(warm_rows)
        self.reset_state()
        calib = []
        for i, r in enumerate(warm_rows):
            s = self.update_score(r)
            if i >= burnin:
                calib.append(s)
        return calib

    def clone_state(self):
        """Deep-copy only the streaming EWMA state (fitted params are shared,
        immutable after fit). Returns (z_fast_copy, z_slow_copy)."""
        zf = None if self.z_fast is None else self.z_fast.copy()
        zs = None if self.z_slow is None else self.z_slow.copy()
        return zf, zs

    def set_state(self, state):
        zf, zs = state
        self.z_fast = None if zf is None else zf.copy()
        self.z_slow = None if zs is None else zs.copy()
