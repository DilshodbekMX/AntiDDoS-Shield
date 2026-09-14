"""Unit test for the Mahalanobis path: a covariance-aware score must penalize OFF-manifold points
far more than ON-manifold points at the SAME Euclidean distance. Deterministic (fixed seed)."""
import os, sys
import numpy as np
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mahalanobis import MahalanobisPath


def _rows(arr, fa='packets_per_sec', fb='bytes_per_sec'):
    return [{fa: float(a), fb: float(b)} for a, b in arr]


def test_off_manifold_dominates_on_manifold():
    """Benign traffic where pps and bytes rise together (correlation ~0.99). A point far along that
    shared axis (on-manifold, a big-but-proportionate burst) must score d2 << a point the same
    Euclidean distance away but perpendicular to it (off-manifold, pps up while bytes flat)."""
    rng = np.random.default_rng(42)
    t = rng.normal(0, 1, 4000)
    noise = rng.normal(0, 0.05, 4000)
    pps = 100 + 20 * t                      # mean 100, sd 20
    byts = 100 + 20 * t + noise             # almost perfectly correlated with pps
    mp = MahalanobisPath().fit(_rows(np.c_[pps, byts]), ['packets_per_sec', 'bytes_per_sec'])
    assert mp.ok and mp.shrinkage is not None

    mu = mp.mu
    # on-manifold: move along the (1,1) correlation direction; off-manifold: along (1,-1).
    r = 100.0  # same Euclidean offset for both
    on = mu + r * np.array([1.0, 1.0]) / np.sqrt(2)
    off = mu + r * np.array([1.0, -1.0]) / np.sqrt(2)
    d2_on = mp.score({'packets_per_sec': on[0], 'bytes_per_sec': on[1]})
    d2_off = mp.score({'packets_per_sec': off[0], 'bytes_per_sec': off[1]})
    assert d2_off > 10 * d2_on, f"off-manifold d2={d2_off:.1f} not >> on-manifold d2={d2_on:.3f}"


def test_guard_too_few_rows():
    mp = MahalanobisPath().fit(_rows([(1, 1), (2, 2)]), ['packets_per_sec', 'bytes_per_sec'])
    assert not mp.ok
    assert mp.score({'packets_per_sec': 99, 'bytes_per_sec': 0}) == 0.0


def test_cap_and_determinism():
    rng = np.random.default_rng(7)
    X = rng.normal(0, 1, (500, 3))
    rows = [{'a': r[0], 'b': r[1], 'c': r[2]} for r in X]
    m1 = MahalanobisPath().fit(rows, ['a', 'b', 'c'])
    m2 = MahalanobisPath().fit(rows, ['a', 'b', 'c'])
    pt = {'a': 50.0, 'b': -50.0, 'c': 50.0}
    assert m1.score(pt) == m2.score(pt)              # deterministic
    assert m1.score(pt) <= m1.d2_cap                 # capped


if __name__ == '__main__':
    test_off_manifold_dominates_on_manifold()
    test_guard_too_few_rows()
    test_cap_and_determinism()
    print("ok: all mahalanobis unit tests passed")
